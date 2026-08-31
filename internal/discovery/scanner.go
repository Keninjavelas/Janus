package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/yourorg/janus/internal/verification"
)

type ScanRequest struct {
	TargetAddress string
	ServerName    string
	ClientCurves  []string
}

func ScanTarget(ctx context.Context, req ScanRequest) (verification.VerificationEvidence, error) {
	curves := req.ClientCurves
	if len(curves) == 0 {
		curves = []string{"X25519MLKEM768", "X25519"}
	}

	curveIDs, err := verification.CurveIDs(curves)
	if err != nil {
		return verification.VerificationEvidence{}, err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{}, "tcp", req.TargetAddress, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         req.ServerName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curveIDs,
	})
	if err != nil {
		evidence := verification.BuildEvidence(verification.RequiredPosture{}, "discovery-scan", "", "janus-discovery", req.TargetAddress, nil, err.Error(), time.Now())
		evidence.ObservationLevel = "DISCOVERY_DIRECT"
		evidence.ConnectionID = req.TargetAddress
		evidence.Flow = &verification.FlowMetadata{Src: req.TargetAddress, Dst: req.TargetAddress}
		return evidence, nil
	}
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		evidence := verification.BuildEvidence(verification.RequiredPosture{}, "discovery-scan", "", "janus-discovery", req.TargetAddress, nil, err.Error(), time.Now())
		evidence.ObservationLevel = "DISCOVERY_DIRECT"
		evidence.ConnectionID = req.TargetAddress
		evidence.Flow = &verification.FlowMetadata{Src: req.TargetAddress, Dst: req.TargetAddress}
		return evidence, nil
	}

	state := conn.ConnectionState()
	evidence := verification.BuildEvidence(
		verification.RequiredPosture{},
		"discovery-scan",
		verification.ObservedKeyExchange(state),
		"janus-discovery",
		req.TargetAddress,
		&state,
		"",
		time.Now(),
	)
	evidence.ObservationLevel = "DISCOVERY_DIRECT"
	evidence.ConnectionID = req.TargetAddress
	evidence.Flow = &verification.FlowMetadata{
		Src: req.TargetAddress,
		Dst: req.TargetAddress,
	}
	return evidence, nil
}

func ScanInventory(ctx context.Context, inventory *Inventory, requests []ScanRequest) ([]CryptoAsset, error) {
	assets := make([]CryptoAsset, 0, len(requests))
	for _, request := range requests {
		evidence, err := ScanTarget(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", request.TargetAddress, err)
		}
		asset, err := inventory.ObserveEvidence(evidence)
		if err != nil {
			return nil, fmt.Errorf("inventory %s: %w", request.TargetAddress, err)
		}
		assets = append(assets, asset)
	}
	return assets, nil
}
