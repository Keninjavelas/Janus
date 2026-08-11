package verification

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

func RunVerifierCLI(reader io.Reader, writer io.Writer) error {
	var req VerificationRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		return fmt.Errorf("decode verification request: %w", err)
	}

	outcome, err := executeVerification(context.Background(), req)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(writer).Encode(outcome); err != nil {
		return fmt.Errorf("encode verification evidence: %w", err)
	}
	return nil
}

func executeVerification(ctx context.Context, req VerificationRequest) (VerificationOutcome, error) {
	curves, err := CurveIDs(req.ClientCurves)
	if err != nil {
		return VerificationOutcome{}, err
	}

	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         req.ServerName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   append([]tls.CurveID(nil), curves...),
	}

	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", req.TargetAddress, clientConfig)
	if err != nil {
		evidence := BuildEvidence(req.Required, req.DecisionID, "", "tls-verifier", req.ConnectionID, nil, err.Error(), time.Now())
		evidence.ObservationLevel = "SUBPROCESS_DIRECT_TLS_OBSERVATION"
		return VerificationOutcome{Evidence: evidence}, nil
	}
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		evidence := BuildEvidence(req.Required, req.DecisionID, "", "tls-verifier", req.ConnectionID, nil, err.Error(), time.Now())
		evidence.ObservationLevel = "SUBPROCESS_DIRECT_TLS_OBSERVATION"
		return VerificationOutcome{Evidence: evidence}, nil
	}

	state := conn.ConnectionState()
	evidence := BuildEvidence(req.Required, req.DecisionID, ObservedKeyExchange(state), "tls-verifier", req.ConnectionID, &state, "", time.Now())
	evidence.ObservationLevel = "SUBPROCESS_DIRECT_TLS_OBSERVATION"

	outcome := VerificationOutcome{Evidence: evidence}
	if evidence.Status != Compliant {
		outcome.Evidence.ApplicationAccess = AccessDenied
		return outcome, nil
	}

	if req.ApplicationPayload == "" {
		outcome.Evidence.ApplicationAccess = AccessAllowed
		return outcome, nil
	}

	if _, err := conn.Write([]byte(req.ApplicationPayload)); err != nil {
		outcome.Evidence.ApplicationAccess = AccessDenied
		outcome.Evidence.Details = withFallbackDetail(outcome.Evidence.Details, err.Error())
		return outcome, nil
	}

	ack := make([]byte, len("janus-ok"))
	if _, err := io.ReadFull(conn, ack); err != nil {
		outcome.Evidence.ApplicationAccess = AccessDenied
		outcome.Evidence.Details = withFallbackDetail(outcome.Evidence.Details, err.Error())
		return outcome, nil
	}

	outcome.Evidence.ApplicationAccess = AccessAllowed
	outcome.ApplicationACK = string(ack)
	return outcome, nil
}
