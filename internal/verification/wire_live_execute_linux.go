//go:build linux && livecapture

package verification

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	pcapverify "github.com/yourorg/janus/internal/verification/pcap"
)

func executeWireVerification(ctx context.Context, req VerificationRequest) (VerificationOutcome, error) {
	port, err := targetPort(req.TargetAddress)
	if err != nil {
		return wireUnverifiedOutcome(req, err.Error()), nil
	}

	timeout := 5 * time.Second
	if req.CaptureTimeoutMs > 0 {
		timeout = time.Duration(req.CaptureTimeoutMs) * time.Millisecond
	}
	captureCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	inspections, err := pcapverify.InspectLiveCapture(captureCtx, pcapverify.LiveCaptureConfig{
		Interface:   req.ObservationInterface,
		Port:        port,
		SnapLen:     65535,
		Promiscuous: false,
		PollTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		return wireUnverifiedOutcome(req, err.Error()), nil
	}

	inspection, found := selectWireInspection(inspections, port)
	if !found {
		return wireUnverifiedOutcome(req, "no tls server hello observed before capture ended"), nil
	}

	observed := ""
	detail := inspection.Detail
	evidence := BuildEvidence(req.Required, req.DecisionID, observed, "janus-wire-verifier", req.ConnectionID, nil, detail, time.Now())
	evidence.ObservationLevel = "WIRE_LIVE"
	evidence.CaptureInterface = req.ObservationInterface
	evidence.Flow = &FlowMetadata{
		Src: fmt.Sprintf("%s:%d", inspection.Flow.SrcIP, inspection.Flow.SrcPort),
		Dst: fmt.Sprintf("%s:%d", inspection.Flow.DstIP, inspection.Flow.DstPort),
	}

	if inspection.Observation != nil {
		observed = inspection.Observation.GroupName
		evidence = BuildEvidence(req.Required, req.DecisionID, observed, "janus-wire-verifier", req.ConnectionID, nil, detail, time.Now())
		evidence.ObservationLevel = "WIRE_LIVE"
		evidence.CaptureInterface = req.ObservationInterface
		evidence.Flow = &FlowMetadata{
			Src: fmt.Sprintf("%s:%d", inspection.Flow.SrcIP, inspection.Flow.SrcPort),
			Dst: fmt.Sprintf("%s:%d", inspection.Flow.DstIP, inspection.Flow.DstPort),
		}
		evidence.TLSVersion = inspection.Observation.TLSVersion
	}

	if evidence.Status == Compliant {
		evidence.ApplicationAccess = AccessAllowed
	} else {
		evidence.ApplicationAccess = AccessDenied
	}

	return VerificationOutcome{Evidence: evidence}, nil
}

func targetPort(address string) (uint16, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("parse target address %q: %w", address, err)
	}
	portValue, err := strconv.Atoi(portText)
	if err != nil {
		return 0, fmt.Errorf("parse target port %q: %w", portText, err)
	}
	if portValue < 0 || portValue > 65535 {
		return 0, fmt.Errorf("target port %d is out of range", portValue)
	}
	return uint16(portValue), nil
}

func selectWireInspection(inspections []pcapverify.FlowInspection, port uint16) (pcapverify.FlowInspection, bool) {
	for _, inspection := range inspections {
		if inspection.Flow.SrcPort == port && inspection.Status == pcapverify.StatusObserved {
			return inspection, true
		}
	}
	for _, inspection := range inspections {
		if inspection.Flow.SrcPort == port && inspection.Status == pcapverify.StatusUnverified {
			return inspection, true
		}
	}
	return pcapverify.FlowInspection{}, false
}

func wireUnverifiedOutcome(req VerificationRequest, detail string) VerificationOutcome {
	evidence := BuildEvidence(req.Required, req.DecisionID, "", "janus-wire-verifier", req.ConnectionID, nil, detail, time.Now())
	evidence.ObservationLevel = "WIRE_LIVE"
	evidence.CaptureInterface = req.ObservationInterface
	evidence.ApplicationAccess = AccessDenied
	return VerificationOutcome{Evidence: evidence}
}
