package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

func RunWireVerifierCLI(reader io.Reader, writer io.Writer) error {
	var req VerificationRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		return fmt.Errorf("decode live wire verification request: %w", err)
	}

	outcome, err := executeWireVerification(context.Background(), req)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(writer).Encode(outcome); err != nil {
		return fmt.Errorf("encode live wire verification evidence: %w", err)
	}
	return nil
}
