package pcap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestInspectCaptureHybrid(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	pcapData := mustPCAP(t, packetize("10.0.0.1", "10.0.0.2", 443, 50000, 1000, [][]byte{raw})...)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureClassical(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519})
	pcapData := mustPCAP(t, packetize("10.0.0.1", "10.0.0.2", 443, 50001, 2000, [][]byte{raw})...)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519" {
		t.Fatalf("expected X25519 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureSegmentedServerHello(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	chunks := splitPayload(raw, []int{19, 57})
	packets := packetize("10.0.0.1", "10.0.0.2", 443, 50002, 3000, chunks)
	pcapData := mustPCAP(t, packets[1], packets[0], packets[2])

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureExactRetransmission(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	original := testPacket{
		srcIP:   "10.0.0.1",
		dstIP:   "10.0.0.2",
		srcPort: 443,
		dstPort: 50006,
		seq:     6000,
		payload: raw,
	}
	retransmit := testPacket{
		srcIP:   original.srcIP,
		dstIP:   original.dstIP,
		srcPort: original.srcPort,
		dstPort: original.dstPort,
		seq:     original.seq,
		payload: append([]byte(nil), raw...),
	}
	pcapData := mustPCAP(t, original, retransmit)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureOutOfOrderSegments(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	chunks := splitPayload(raw, []int{17, 41, 73})
	packets := packetize("10.0.0.1", "10.0.0.2", 443, 50007, 7000, chunks)
	pcapData := mustPCAP(t, packets[2], packets[0], packets[3], packets[1])

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureIdenticalOverlap(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	first := raw[:64]
	second := raw[48:]
	pcapData := mustPCAP(t,
		testPacket{
			srcIP:   "10.0.0.1",
			dstIP:   "10.0.0.2",
			srcPort: 443,
			dstPort: 50008,
			seq:     8000,
			payload: first,
		},
		testPacket{
			srcIP:   "10.0.0.1",
			dstIP:   "10.0.0.2",
			srcPort: 443,
			dstPort: 50008,
			seq:     8048,
			payload: second,
		},
	)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusObserved {
		t.Fatalf("expected observed status, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].Observation == nil || results[0].Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768 observation, got %#v", results[0].Observation)
	}
}

func TestInspectCaptureConflictingOverlapUnverified(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	first := append([]byte(nil), raw[:64]...)
	second := append([]byte(nil), raw[48:]...)
	second[4] ^= 0xFF
	pcapData := mustPCAP(t,
		testPacket{
			srcIP:   "10.0.0.1",
			dstIP:   "10.0.0.2",
			srcPort: 443,
			dstPort: 50009,
			seq:     9000,
			payload: first,
		},
		testPacket{
			srcIP:   "10.0.0.1",
			dstIP:   "10.0.0.2",
			srcPort: 443,
			dstPort: 50009,
			seq:     9048,
			payload: second,
		},
	)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusUnverified {
		t.Fatalf("expected unverified status, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestInspectCaptureIgnoresUnrelatedTraffic(t *testing.T) {
	pcapData := mustPCAP(t, testPacket{
		srcIP:   "10.0.0.10",
		dstIP:   "10.0.0.20",
		srcPort: 8080,
		dstPort: 51000,
		seq:     1,
		payload: []byte("GET / HTTP/1.1\r\nHost: janus.local\r\n\r\n"),
	})

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusIgnored {
		t.Fatalf("expected ignored status, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestInspectCaptureIncompleteServerHelloUnverified(t *testing.T) {
	raw := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	truncated := truncateServerHelloRecord(t, raw, 7)
	pcapData := mustPCAP(t, packetize("10.0.0.1", "10.0.0.2", 443, 50003, 4000, [][]byte{truncated})...)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flow result, got %d", len(results))
	}
	if results[0].Status != StatusUnverified {
		t.Fatalf("expected unverified status, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestInspectCaptureConcurrentFlowsRemainIsolated(t *testing.T) {
	hybrid := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	classical := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519})

	hybridPackets := packetize("10.0.0.1", "10.0.0.2", 443, 50004, 5000, splitPayload(hybrid, []int{23}))
	classicalPackets := packetize("10.0.0.1", "10.0.0.3", 443, 50005, 9000, splitPayload(classical, []int{31}))
	pcapData := mustPCAP(t,
		hybridPackets[0],
		classicalPackets[0],
		hybridPackets[1],
		classicalPackets[1],
	)

	results, err := InspectCapture(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 flow results, got %d", len(results))
	}

	byPort := make(map[uint16]FlowInspection, len(results))
	for _, result := range results {
		byPort[result.Flow.DstPort] = result
	}

	if result, ok := byPort[50004]; !ok || result.Status != StatusObserved || result.Observation == nil || result.Observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected hybrid flow to stay isolated, got %#v", result)
	}
	if result, ok := byPort[50005]; !ok || result.Status != StatusObserved || result.Observation == nil || result.Observation.GroupName != "X25519" {
		t.Fatalf("expected classical flow to stay isolated, got %#v", result)
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

func mustPCAP(t *testing.T, packets ...testPacket) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	timestamp := time.Unix(0, 0)
	for _, packet := range packets {
		data := mustSerializePacket(t, packet)
		ci := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(ci, data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
		timestamp = timestamp.Add(time.Millisecond)
	}

	return buf.Bytes()
}

func mustSerializePacket(t *testing.T, packet testPacket) []byte {
	t.Helper()

	srcIP := net.ParseIP(packet.srcIP).To4()
	dstIP := net.ParseIP(packet.dstIP).To4()
	if srcIP == nil || dstIP == nil {
		t.Fatal("test packet requires valid IPv4 addresses")
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
		t.Fatalf("set tcp checksum network layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, tcp, gopacket.Payload(packet.payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	return buffer.Bytes()
}

func splitPayload(data []byte, breakpoints []int) [][]byte {
	var segments [][]byte
	start := 0
	for _, point := range breakpoints {
		if point > len(data) {
			break
		}
		segments = append(segments, append([]byte(nil), data[start:point]...))
		start = point
	}
	if start < len(data) {
		segments = append(segments, append([]byte(nil), data[start:]...))
	}
	return segments
}

func captureServerHandshakeBytes(t *testing.T, serverCurves, clientCurves []tls.CurveID) []byte {
	t.Helper()

	serverRaw, clientRaw := net.Pipe()
	recorder := &recordingConn{Conn: serverRaw}

	cert := mustSelfSignedCert(t)
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
			t.Fatalf("handshake failed: %v", err)
		}
	}

	_ = serverTLS.Close()
	_ = clientTLS.Close()
	return recorder.Bytes()
}

func truncateServerHelloRecord(t *testing.T, data []byte, trim int) []byte {
	t.Helper()

	offset := 0
	for offset+5 <= len(data) {
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		recordEnd := offset + 5 + recordLen
		if recordEnd > len(data) {
			t.Fatal("fixture already contains incomplete record")
		}
		if data[offset] == 22 && len(data[offset+5:recordEnd]) >= 1 && data[offset+5] == 2 {
			if recordEnd-trim <= offset+5 {
				t.Fatal("trim would remove entire server hello record")
			}
			return append([]byte(nil), data[:recordEnd-trim]...)
		}
		offset = recordEnd
	}

	t.Fatal("server hello record not found")
	return nil
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

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
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
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}
