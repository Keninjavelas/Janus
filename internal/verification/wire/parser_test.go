package wire

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
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestObserveServerHelloHybrid(t *testing.T) {
	data := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})

	observation, err := ObserveServerHello(data)
	if err != nil {
		t.Fatalf("observe server hello: %v", err)
	}
	if observation.TLSVersion != "TLS 1.3" {
		t.Fatalf("expected TLS 1.3, got %s", observation.TLSVersion)
	}
	if observation.GroupID != groupX25519MLKEM768 {
		t.Fatalf("expected group id 0x11EC, got 0x%04X", observation.GroupID)
	}
	if observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768, got %s", observation.GroupName)
	}
}

func TestObserveServerHelloClassical(t *testing.T) {
	data := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519})

	observation, err := ObserveServerHello(data)
	if err != nil {
		t.Fatalf("observe server hello: %v", err)
	}
	if observation.GroupID != groupX25519 {
		t.Fatalf("expected group id 0x001D, got 0x%04X", observation.GroupID)
	}
	if observation.GroupName != "X25519" {
		t.Fatalf("expected X25519, got %s", observation.GroupName)
	}
}

func TestObserveServerHelloMalformed(t *testing.T) {
	data := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	malformed := append([]byte(nil), data...)

	keyShareOffset := bytes.Index(malformed, []byte{0x00, 0x33})
	if keyShareOffset == -1 {
		t.Fatal("key_share extension not found in fixture")
	}
	malformed[keyShareOffset+2] = 0x00
	malformed[keyShareOffset+3] = 0x01

	_, err := ObserveServerHello(malformed)
	if err == nil {
		t.Fatal("expected malformed parse error")
	}
	if !errors.Is(err, ErrMalformedServerHello) {
		t.Fatalf("expected malformed server hello error, got %v", err)
	}
}

func TestObserveServerHelloTruncated(t *testing.T) {
	data := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	truncated := truncateServerHelloRecord(t, data, 7)

	_, err := ObserveServerHello(truncated)
	if err == nil {
		t.Fatal("expected truncated parse error")
	}
	if !errors.Is(err, ErrIncompleteRecord) {
		t.Fatalf("expected incomplete record error, got %v", err)
	}
}

func TestObserveServerHelloSegmented(t *testing.T) {
	data := captureServerHandshakeBytes(t, []tls.CurveID{tls.X25519MLKEM768}, []tls.CurveID{tls.X25519MLKEM768})
	segments := splitSegments(data, []int{3, 11, 29, 57})

	var observer StreamObserver
	var observation *Observation
	for _, chunk := range segments {
		var err error
		observation, err = observer.Feed(chunk)
		if err != nil {
			t.Fatalf("feed chunk: %v", err)
		}
	}

	if observation == nil {
		t.Fatal("expected observation after final segment")
	}
	if observation.GroupName != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768, got %s", observation.GroupName)
	}
}

type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
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

func splitSegments(data []byte, breakpoints []int) [][]byte {
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

func truncateServerHelloRecord(t *testing.T, data []byte, trim int) []byte {
	t.Helper()

	offset := 0
	for offset+5 <= len(data) {
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		recordEnd := offset + 5 + recordLen
		if recordEnd > len(data) {
			t.Fatal("fixture already contains incomplete record")
		}
		if data[offset] == recordTypeHandshake && len(data[offset+5:recordEnd]) >= 1 && data[offset+5] == handshakeTypeServerHello {
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
