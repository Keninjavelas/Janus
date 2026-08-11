//go:build linux && livecapture

package verification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveWireVerificationCompliant(t *testing.T) {
	requireLiveCapturePrivileges(t)

	required := mustRequiredPosture(t)
	outcome := runLiveWireScenario(t, liveWireScenario{
		Required:     required,
		ServerCurves: []string{"X25519MLKEM768"},
		ClientCurves: []string{"X25519MLKEM768"},
	})

	if outcome.Evidence.Status != Compliant {
		t.Fatalf("expected %s, got %s (%s)", Compliant, outcome.Evidence.Status, outcome.Evidence.Details)
	}
	if outcome.Evidence.Observed != "X25519MLKEM768" {
		t.Fatalf("expected X25519MLKEM768, got %s", outcome.Evidence.Observed)
	}
	if outcome.Evidence.ObservationLevel != "WIRE_LIVE" {
		t.Fatalf("expected WIRE_LIVE, got %s", outcome.Evidence.ObservationLevel)
	}
	if outcome.Evidence.ApplicationAccess != AccessAllowed {
		t.Fatalf("expected %s, got %s", AccessAllowed, outcome.Evidence.ApplicationAccess)
	}
	if outcome.Evidence.CaptureInterface == "" {
		t.Fatal("expected capture interface metadata")
	}
	if outcome.Evidence.Flow == nil {
		t.Fatal("expected flow metadata")
	}
}

func TestLiveWireVerificationNonCompliant(t *testing.T) {
	requireLiveCapturePrivileges(t)

	required := mustRequiredPosture(t)
	outcome := runLiveWireScenario(t, liveWireScenario{
		Required:     required,
		ServerCurves: []string{"X25519"},
		ClientCurves: []string{"X25519"},
	})

	if outcome.Evidence.Status != NonCompliant {
		t.Fatalf("expected %s, got %s (%s)", NonCompliant, outcome.Evidence.Status, outcome.Evidence.Details)
	}
	if outcome.Evidence.Observed != "X25519" {
		t.Fatalf("expected X25519, got %s", outcome.Evidence.Observed)
	}
	if outcome.Evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected %s, got %s", AccessDenied, outcome.Evidence.ApplicationAccess)
	}
}

func TestLiveWireVerificationUnverifiedWhenNoTrafficObserved(t *testing.T) {
	requireLiveCapturePrivileges(t)

	iface := mustLoopbackInterface(t)
	required := mustRequiredPosture(t)
	address := reserveUnusedLoopbackAddress(t)

	outcome := runWireVerifierProcess(t, VerificationRequest{
		DecisionID:           "decision-live-unverified",
		ConnectionID:         "conn-live-unverified",
		Required:             required,
		TargetAddress:        address,
		ServerName:           "janus.local",
		ObservationInterface: iface,
		CaptureTimeoutMs:     1200,
	})

	if outcome.Evidence.Status != Unverified {
		t.Fatalf("expected %s, got %s (%s)", Unverified, outcome.Evidence.Status, outcome.Evidence.Details)
	}
	if outcome.Evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected %s, got %s", AccessDenied, outcome.Evidence.ApplicationAccess)
	}
	if outcome.Evidence.ObservationLevel != "WIRE_LIVE" {
		t.Fatalf("expected WIRE_LIVE, got %s", outcome.Evidence.ObservationLevel)
	}
}

func TestWireLiveVerifierHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_JANUS_WIRE_VERIFIER_HELPER") != "1" {
		return
	}
	if err := RunWireVerifierCLI(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestWireLiveServerHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_JANUS_WIRE_SERVER_HELPER") != "1" {
		return
	}

	curves, err := helperCurveIDs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer listener.Close()

	if err := os.WriteFile(os.Getenv("JANUS_SERVER_ADDR_FILE"), []byte(listener.Addr().String()), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	conn, err := listener.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = io.Copy(io.Discard, tlsConn)
	os.Exit(0)
}

func TestWireLiveClientHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_JANUS_WIRE_CLIENT_HELPER") != "1" {
		return
	}

	curves, err := helperCurveIDs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "janus.local",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
	}

	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", os.Getenv("JANUS_TARGET_ADDR"), clientConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type liveWireScenario struct {
	Required     RequiredPosture
	ServerCurves []string
	ClientCurves []string
}

func runLiveWireScenario(t *testing.T, scenario liveWireScenario) VerificationOutcome {
	t.Helper()

	iface := mustLoopbackInterface(t)
	addrFile := filepath.Join(t.TempDir(), "server-addr.txt")
	readyFile := filepath.Join(t.TempDir(), "wire-ready.txt")

	serverCmd, serverStderr := startHelperProcess(t, "GO_WANT_JANUS_WIRE_SERVER_HELPER", []string{
		"JANUS_SERVER_ADDR_FILE=" + addrFile,
		"JANUS_HELPER_CURVES=" + strings.Join(scenario.ServerCurves, ","),
	})
	defer killProcess(serverCmd.Process)

	address := waitForServerAddress(t, addrFile)
	verifierReq := VerificationRequest{
		DecisionID:           "decision-live-wire",
		ConnectionID:         "conn-live-wire",
		Required:             scenario.Required,
		TargetAddress:        address,
		ServerName:           "janus.local",
		ObservationInterface: iface,
		CaptureTimeoutMs:     4000,
	}

	payload, err := json.Marshal(verifierReq)
	if err != nil {
		t.Fatalf("marshal verifier request: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	verifierCmd := exec.Command(exe, "-test.run=TestWireLiveVerifierHelperProcess")
	verifierCmd.Env = append(os.Environ(),
		"GO_WANT_JANUS_WIRE_VERIFIER_HELPER=1",
		"JANUS_WIRE_READY_FILE="+readyFile,
	)
	verifierCmd.Stdin = bytes.NewReader(payload)
	var verifierStdout bytes.Buffer
	var verifierStderr bytes.Buffer
	verifierCmd.Stdout = &verifierStdout
	verifierCmd.Stderr = &verifierStderr
	if err := verifierCmd.Start(); err != nil {
		t.Fatalf("start verifier helper: %v", err)
	}

	waitForReadySignal(t, readyFile)

	clientCmd, clientStderr := startHelperProcess(t, "GO_WANT_JANUS_WIRE_CLIENT_HELPER", []string{
		"JANUS_TARGET_ADDR=" + address,
		"JANUS_HELPER_CURVES=" + strings.Join(scenario.ClientCurves, ","),
	})

	if err := clientCmd.Wait(); err != nil {
		t.Fatalf("client helper failed: %v: %s", err, clientStderr.String())
	}
	if err := verifierCmd.Wait(); err != nil {
		t.Fatalf("verifier helper failed: %v: %s", err, verifierStderr.String())
	}
	if err := serverCmd.Wait(); err != nil {
		t.Fatalf("server helper failed: %v: %s", err, serverStderr.String())
	}

	var outcome VerificationOutcome
	if err := json.Unmarshal(verifierStdout.Bytes(), &outcome); err != nil {
		t.Fatalf("decode verifier outcome: %v", err)
	}
	return outcome
}

func runWireVerifierProcess(t *testing.T, req VerificationRequest) VerificationOutcome {
	t.Helper()

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal verifier request: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=TestWireLiveVerifierHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_JANUS_WIRE_VERIFIER_HELPER=1")
	cmd.Stdin = bytes.NewReader(payload)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("wire verifier helper failed: %v: %s", err, stderr.String())
	}

	var outcome VerificationOutcome
	if err := json.Unmarshal(stdout.Bytes(), &outcome); err != nil {
		t.Fatalf("decode verifier outcome: %v", err)
	}
	return outcome
}

func startHelperProcess(t *testing.T, marker string, extraEnv []string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run="+helperTestName(marker))
	cmd.Env = append(os.Environ(), append([]string{marker + "=1"}, extraEnv...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", marker, err)
	}
	return cmd, &stderr
}

func helperTestName(marker string) string {
	switch marker {
	case "GO_WANT_JANUS_WIRE_SERVER_HELPER":
		return "TestWireLiveServerHelperProcess"
	case "GO_WANT_JANUS_WIRE_CLIENT_HELPER":
		return "TestWireLiveClientHelperProcess"
	default:
		return "TestWireLiveVerifierHelperProcess"
	}
}

func waitForServerAddress(t *testing.T, path string) string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(bytes.TrimSpace(data)) > 0 {
			return string(bytes.TrimSpace(data))
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for server address in %s", path)
	return ""
}

func waitForReadySignal(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte("JANUS_WIRE_READY")) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for verifier readiness signal in %s", path)
}

func helperCurveIDs() ([]tls.CurveID, error) {
	curveText := os.Getenv("JANUS_HELPER_CURVES")
	if curveText == "" {
		return nil, fmt.Errorf("JANUS_HELPER_CURVES is required")
	}
	return CurveIDs(strings.Split(curveText, ","))
}

func mustLoopbackInterface(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	t.Fatal("no active loopback interface found")
	return ""
}

func reserveUnusedLoopbackAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func requireLiveCapturePrivileges(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("live capture tests require root or CAP_NET_RAW/CAP_NET_ADMIN")
	}
}

func killProcess(process *os.Process) {
	if process != nil {
		_ = process.Kill()
	}
}
