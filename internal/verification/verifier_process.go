package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Verifier interface {
	Verify(context.Context, VerificationRequest) (VerificationOutcome, error)
}

type InProcessVerifier struct{}

func (InProcessVerifier) Verify(ctx context.Context, req VerificationRequest) (VerificationOutcome, error) {
	return executeVerification(ctx, req)
}

type ExecutableVerifier struct {
	Path string
	Args []string
	Env  []string
}

func (v ExecutableVerifier) Verify(ctx context.Context, req VerificationRequest) (VerificationOutcome, error) {
	if v.Path == "" {
		return VerificationOutcome{}, fmt.Errorf("verifier executable path is required")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return VerificationOutcome{}, err
	}

	cmd := exec.CommandContext(ctx, v.Path, v.Args...)
	cmd.Env = append(os.Environ(), v.Env...)
	cmd.Stdin = bytes.NewReader(payload)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return VerificationOutcome{}, fmt.Errorf("verifier process failed: %w: %s", err, stderr.String())
		}
		return VerificationOutcome{}, fmt.Errorf("verifier process failed: %w", err)
	}

	var outcome VerificationOutcome
	if err := json.Unmarshal(stdout.Bytes(), &outcome); err != nil {
		return VerificationOutcome{}, fmt.Errorf("decode verifier output: %w", err)
	}
	return outcome, nil
}
