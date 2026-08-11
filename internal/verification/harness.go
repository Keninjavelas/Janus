package verification

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
)

type TLSHarnessConfig struct {
	Required           RequiredPosture
	ServerCurves       []tls.CurveID
	ClientCurves       []tls.CurveID
	Verifier           Verifier
	ApplicationPayload []byte
}

type TLSHarnessResult struct {
	Evidence       VerificationEvidence
	TrafficAllowed bool
	ApplicationACK string
}

func RunTLSVerification(ctx context.Context, cfg TLSHarnessConfig) (TLSHarnessResult, error) {
	connID, err := randomID()
	if err != nil {
		return TLSHarnessResult{}, err
	}
	decisionID, err := randomID()
	if err != nil {
		return TLSHarnessResult{}, err
	}

	if cfg.Verifier == nil {
		cfg.Verifier = InProcessVerifier{}
	}
	if len(cfg.ApplicationPayload) == 0 {
		cfg.ApplicationPayload = []byte("janus-application-data")
	}

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		return TLSHarnessResult{}, err
	}

	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), cfg.ServerCurves...),
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		return TLSHarnessResult{}, err
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			serverErrCh <- err
			return
		}

		if err := tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			serverErrCh <- err
			return
		}

		buf := make([]byte, len(cfg.ApplicationPayload))
		n, err := io.ReadFull(tlsConn, buf)
		switch {
		case err == nil:
			if _, err := tlsConn.Write([]byte("janus-ok")); err != nil {
				serverErrCh <- err
				return
			}
			serverErrCh <- nil
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			if n == 0 {
				serverErrCh <- nil
				return
			}
			serverErrCh <- err
		case isTimeout(err):
			serverErrCh <- nil
		default:
			serverErrCh <- err
		}
	}()

	outcome, verifyErr := cfg.Verifier.Verify(ctx, VerificationRequest{
		DecisionID:         decisionID,
		ConnectionID:       connID,
		Required:           cfg.Required,
		TargetAddress:      listener.Addr().String(),
		ServerName:         "janus.local",
		ClientCurves:       CurveNames(cfg.ClientCurves),
		ApplicationPayload: string(cfg.ApplicationPayload),
	})
	if verifyErr != nil {
		evidence := BuildEvidence(cfg.Required, decisionID, "", "tls-verifier", connID, nil, verifyErr.Error(), time.Now())
		evidence.ObservationLevel = "SUBPROCESS_DIRECT_TLS_OBSERVATION"
		evidence.ApplicationAccess = AccessDenied
		return TLSHarnessResult{
			Evidence:       evidence,
			TrafficAllowed: false,
		}, nil
	}

	result := TLSHarnessResult{
		Evidence:       outcome.Evidence,
		TrafficAllowed: outcome.Evidence.ApplicationAccess == AccessAllowed,
		ApplicationACK: outcome.ApplicationACK,
	}

	select {
	case err := <-serverErrCh:
		if err != nil {
			return result, err
		}
	case <-ctx.Done():
		return result, ctx.Err()
	}

	return result, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func randomID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func generateSelfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
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
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
