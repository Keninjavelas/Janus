package benchmarks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/config"
	"github.com/yourorg/janus/internal/discovery"
	"github.com/yourorg/janus/internal/fallback"
	"github.com/yourorg/janus/internal/migration"
	"github.com/yourorg/janus/internal/risk"
	"github.com/yourorg/janus/internal/verification"
	pcapverify "github.com/yourorg/janus/internal/verification/pcap"
	"github.com/yourorg/janus/internal/verification/wire"
)

var benchmarkPolicyOnce sync.Once

func BenchmarkPolicyDecisionLatency(b *testing.B) {
	benchmarkPolicyOnce.Do(func() {
		_ = config.InitLoader(filepath.Join("..", "..", "configs", "policy.yaml"))
	})

	req := &pb.ContextRequest{
		Scenario:        "MICROSEGMENTATION",
		Region:          "EU",
		Risk:            4,
		DeviceType:      "iot",
		LatencyBudgetMs: 2.0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fallback.EvaluateWithFallback(context.Background(), req); err != nil {
			b.Fatalf("evaluate fallback: %v", err)
		}
	}
}

func BenchmarkWireParserThroughput(b *testing.B) {
	data := captureServerHandshakeBytes(b, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := wire.ObserveServerHello(data); err != nil {
			b.Fatalf("observe server hello: %v", err)
		}
	}
}

func BenchmarkOfflinePCAPInspectionThroughput(b *testing.B) {
	raw := captureServerHandshakeBytes(b, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	pcapData := mustPCAP(b, packetize("10.0.0.1", "10.0.0.2", 443, 50000, 1000, [][]byte{raw})...)
	b.SetBytes(int64(len(pcapData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pcapverify.InspectCapture(bytes.NewReader(pcapData)); err != nil {
			b.Fatalf("inspect pcap: %v", err)
		}
	}
}

func BenchmarkDiscoveryInventoryObserve(b *testing.B) {
	inventory := discovery.NewInventory()
	evidence := verification.VerificationEvidence{
		Observed:         "X25519MLKEM768",
		Status:           verification.Compliant,
		ObservationLevel: "WIRE_LIVE",
		TLSVersion:       "TLS 1.3",
		Flow: &verification.FlowMetadata{
			Src: "127.0.0.1:8443",
			Dst: "127.0.0.1:50123",
		},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := inventory.ObserveEvidence(evidence); err != nil {
			b.Fatalf("observe inventory evidence: %v", err)
		}
	}
}

func BenchmarkRiskEvaluation(b *testing.B) {
	input := risk.Input{
		Asset: discovery.CryptoAsset{
			ID:               "10.0.0.8:443/TLS",
			Host:             "10.0.0.8",
			Port:             443,
			KeyExchange:      "X25519",
			KeyExchangeClass: "CLASSICAL",
			QuantumSafe:      false,
		},
		DataSensitivity:      "restricted",
		ConfidentialityYears: 30,
		AssetCriticality:     "critical",
		ExternalExposure:     true,
		MigrationReady:       true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = risk.Evaluate(input)
	}
}

func BenchmarkMigrationVerification(b *testing.B) {
	plan := migration.BuildPlan(discovery.CryptoAsset{
		ID:          "10.0.0.8:443/TLS",
		Host:        "10.0.0.8",
		KeyExchange: "X25519",
		QuantumSafe: false,
	}, risk.Assessment{Risk: risk.Critical, Priority: risk.P0}, nil, migration.ModeEnforce)
	evidence := verification.VerificationEvidence{
		Required:     "X25519MLKEM768",
		Observed:     "X25519MLKEM768",
		Status:       verification.Compliant,
		ConnectionID: "bench-conn",
		Timestamp:    time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = migration.VerifyPlan(plan, evidence)
	}
}

type testPacket struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	seq     uint32
	payload []byte
}

type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.buf.Write(p)
	return c.Conn.Write(p)
}

func (c *recordingConn) Bytes() []byte {
	return append([]byte(nil), c.buf.Bytes()...)
}

func packetize(srcIP, dstIP string, srcPort, dstPort uint16, startSeq uint32, chunks [][]byte) []testPacket {
	packets := make([]testPacket, 0, len(chunks))
	seq := startSeq
	for _, chunk := range chunks {
		packets = append(packets, testPacket{
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: srcPort,
			dstPort: dstPort,
			seq:     seq,
			payload: append([]byte(nil), chunk...),
		})
		seq += uint32(len(chunk))
	}
	return packets
}

func mustPCAP(tb testing.TB, packets ...testPacket) []byte {
	tb.Helper()

	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		tb.Fatalf("write pcap header: %v", err)
	}

	timestamp := time.Unix(0, 0)
	for _, packet := range packets {
		data := mustSerializePacket(tb, packet)
		ci := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(ci, data); err != nil {
			tb.Fatalf("write packet: %v", err)
		}
		timestamp = timestamp.Add(time.Millisecond)
	}

	return buf.Bytes()
}

func mustSerializePacket(tb testing.TB, packet testPacket) []byte {
	tb.Helper()

	srcIP := net.ParseIP(packet.srcIP).To4()
	dstIP := net.ParseIP(packet.dstIP).To4()
	if srcIP == nil || dstIP == nil {
		tb.Fatal("benchmark packet requires valid IPv4 addresses")
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(packet.srcPort),
		DstPort: layers.TCPPort(packet.dstPort),
		Seq:     packet.seq,
		ACK:     true,
		PSH:     true,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		tb.Fatalf("set checksum network layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, tcp, gopacket.Payload(packet.payload)); err != nil {
		tb.Fatalf("serialize packet: %v", err)
	}
	return buffer.Bytes()
}

func captureServerHandshakeBytes(tb testing.TB, serverCurves, clientCurves []tls.CurveID) []byte {
	tb.Helper()

	serverRaw, clientRaw := net.Pipe()
	recorder := &recordingConn{Conn: serverRaw}

	cert := mustSelfSignedCert(tb)
	serverTLS := tls.Server(recorder, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), serverCurves...),
	})
	clientTLS := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "janus.local",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   append([]tls.CurveID(nil), clientCurves...),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- serverTLS.HandshakeContext(ctx) }()
	go func() { errCh <- clientTLS.HandshakeContext(ctx) }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			tb.Fatalf("handshake failed: %v", err)
		}
	}

	_ = serverTLS.Close()
	_ = clientTLS.Close()
	return recorder.Bytes()
}

func mustSelfSignedCert(tb testing.TB) tls.Certificate {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate rsa key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "janus.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"janus.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		tb.Fatalf("load key pair: %v", err)
	}
	return cert
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
