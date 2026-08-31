//go:build linux && livecapture

package verification

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/yourorg/janus/internal/verification/attribution"
	pcapverify "github.com/yourorg/janus/internal/verification/pcap"
)

var resolveLocalFlowAttribution = attribution.ResolveLocalSourceOwner

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

	var mu sync.Mutex
	attributionCache := make(map[pcapverify.FlowKey]attribution.Result)

	onTCPPacket := func(srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
		var serverFlow pcapverify.FlowKey
		if srcPort == port {
			serverFlow = pcapverify.FlowKey{
				SrcIP:   srcIP,
				SrcPort: srcPort,
				DstIP:   dstIP,
				DstPort: dstPort,
			}
		} else if dstPort == port {
			serverFlow = pcapverify.FlowKey{
				SrcIP:   dstIP,
				SrcPort: dstPort,
				DstIP:   srcIP,
				DstPort: srcPort,
			}
		} else {
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if _, exists := attributionCache[serverFlow]; exists {
			return
		}
		res, err := resolveLocalFlowAttribution(attribution.Flow{
			SrcIP:   serverFlow.SrcIP,
			SrcPort: serverFlow.SrcPort,
			DstIP:   serverFlow.DstIP,
			DstPort: serverFlow.DstPort,
		})
		if err == nil && res.Status == attribution.Attributed {
			attributionCache[serverFlow] = res
		}
	}

	inspections, err := pcapverify.InspectLiveCapture(captureCtx, pcapverify.LiveCaptureConfig{
		Interface:   req.ObservationInterface,
		Port:        port,
		SnapLen:     65535,
		Promiscuous: false,
		PollTimeout: 100 * time.Millisecond,
		OnTCPPacket: onTCPPacket,
	})
	if err != nil {
		return wireUnverifiedOutcome(req, err.Error()), nil
	}

	inspection, found := selectWireInspection(inspections.Inspections, port)
	if !found {
		return wireUnverifiedOutcome(req, withLiveCaptureDiagnostics("no tls server hello observed before capture ended", inspections.Diagnostics)), nil
	}

	evidence := buildWireLiveEvidence(req, inspection, inspections.Diagnostics, attributionCache)

	if evidence.Status == Compliant {
		evidence.ApplicationAccess = AccessAllowed
	} else {
		evidence.ApplicationAccess = AccessDenied
	}

	return VerificationOutcome{Evidence: evidence}, nil
}

func buildWireLiveEvidence(req VerificationRequest, inspection pcapverify.FlowInspection, diagnostics pcapverify.LiveCaptureDiagnostics, attributionCache map[pcapverify.FlowKey]attribution.Result) VerificationEvidence {
	observed := ""
	detail := inspection.Detail
	if inspection.Status == pcapverify.StatusUnverified {
		detail = withLiveCaptureDiagnostics(detail, diagnostics)
	}
	if inspection.Observation != nil {
		observed = inspection.Observation.GroupName
	}

	evidence := BuildEvidence(req.Required, req.DecisionID, observed, "janus-wire-verifier", req.ConnectionID, nil, detail, time.Now())
	evidence.ObservationLevel = "WIRE_LIVE"
	evidence.CaptureInterface = req.ObservationInterface
	evidence.Flow = &FlowMetadata{
		Src: fmt.Sprintf("%s:%d", inspection.Flow.SrcIP, inspection.Flow.SrcPort),
		Dst: fmt.Sprintf("%s:%d", inspection.Flow.DstIP, inspection.Flow.DstPort),
	}
	if inspection.Observation != nil {
		evidence.TLSVersion = inspection.Observation.TLSVersion
	}

	if snapshotted, ok := attributionCache[inspection.Flow]; ok && snapshotted.Status == attribution.Attributed {
		ApplyAttributionResult(&evidence, snapshotted)
	} else {
		attachWireFlowAttribution(&evidence, inspection.Flow)
	}
	return evidence
}

func attachWireFlowAttribution(evidence *VerificationEvidence, flow pcapverify.FlowKey) {
	result, err := resolveLocalFlowAttribution(attribution.Flow{
		SrcIP:   flow.SrcIP,
		SrcPort: flow.SrcPort,
		DstIP:   flow.DstIP,
		DstPort: flow.DstPort,
	})
	if err != nil {
		if result.Status == "" {
			result.Status = attribution.Unattributed
		}
		if result.Detail == "" {
			result.Detail = err.Error()
		}
	}
	ApplyAttributionResult(evidence, result)
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

func withLiveCaptureDiagnostics(detail string, diagnostics pcapverify.LiveCaptureDiagnostics) string {
	return fmt.Sprintf("%s; live capture diagnostics: %s", detail, diagnostics.String())
}
