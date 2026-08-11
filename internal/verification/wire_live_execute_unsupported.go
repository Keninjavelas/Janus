//go:build !linux || !livecapture

package verification

import (
	"context"
	"time"
)

func executeWireVerification(_ context.Context, req VerificationRequest) (VerificationOutcome, error) {
	evidence := BuildEvidence(
		req.Required,
		req.DecisionID,
		"",
		"janus-wire-verifier",
		req.ConnectionID,
		nil,
		"live wire verification requires linux with the livecapture build tag",
		time.Now(),
	)
	evidence.ObservationLevel = "WIRE_LIVE"
	evidence.CaptureInterface = req.ObservationInterface
	return VerificationOutcome{Evidence: evidence}, nil
}
