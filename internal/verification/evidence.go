package verification

import (
	"crypto/tls"
	"fmt"
	"time"

	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/verification/attribution"
)

type ComplianceStatus string
type ApplicationAccess string
type AttributionStatus string

type FlowMetadata struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

type WorkloadMetadata struct {
	PID                   int    `json:"pid"`
	Executable            string `json:"executable"`
	ProcessStartTimeTicks uint64 `json:"process_start_time_ticks,omitempty"`
	SocketInode           string `json:"socket_inode,omitempty"`
	AttributionBasis      string `json:"attribution_basis,omitempty"`
}

const (
	Compliant    ComplianceStatus = "COMPLIANT"
	NonCompliant ComplianceStatus = "NON_COMPLIANT"
	Unverified   ComplianceStatus = "UNVERIFIED"

	AccessAllowed ApplicationAccess = "ALLOWED"
	AccessDenied  ApplicationAccess = "DENIED"

	Attributed   AttributionStatus = "ATTRIBUTED"
	Unattributed AttributionStatus = "UNATTRIBUTED"
	Ambiguous    AttributionStatus = "AMBIGUOUS"
)

type RequiredPosture struct {
	KeyExchange   string
	PolicyVersion string
}

type VerificationEvidence struct {
	DecisionID           string            `json:"decision_id"`
	Required             string            `json:"required"`
	Observed             string            `json:"observed"`
	Status               ComplianceStatus  `json:"status"`
	ApplicationAccess    ApplicationAccess `json:"application_access"`
	Source               string            `json:"source"`
	ConnectionID         string            `json:"connection_id"`
	Timestamp            time.Time         `json:"timestamp"`
	PolicyVersion        string            `json:"policy_version"`
	TLSVersion           string            `json:"tls_version,omitempty"`
	CipherSuite          string            `json:"cipher_suite,omitempty"`
	CertificateSignature string            `json:"certificate_signature,omitempty"`
	Details              string            `json:"details,omitempty"`
	ObservationLevel     string            `json:"observation_level,omitempty"`
	CaptureInterface     string            `json:"interface,omitempty"`
	Flow                 *FlowMetadata     `json:"flow,omitempty"`
	AttributionStatus    AttributionStatus `json:"attribution_status,omitempty"`
	AttributionDetail    string            `json:"attribution_detail,omitempty"`
	Workload             *WorkloadMetadata `json:"workload,omitempty"`
}

type VerificationRequest struct {
	DecisionID           string          `json:"decision_id"`
	ConnectionID         string          `json:"connection_id"`
	Required             RequiredPosture `json:"required"`
	TargetAddress        string          `json:"target_address"`
	ServerName           string          `json:"server_name"`
	ClientCurves         []string        `json:"client_curves"`
	ObservationInterface string          `json:"observation_interface,omitempty"`
	CaptureTimeoutMs     int             `json:"capture_timeout_ms,omitempty"`
	ApplicationPayload   string          `json:"application_payload,omitempty"`
}

type VerificationOutcome struct {
	Evidence       VerificationEvidence `json:"evidence"`
	ApplicationACK string               `json:"application_ack,omitempty"`
}

func RequiredPostureFromAlgorithmConfig(cfg *pb.AlgorithmConfig, policyVersion string) RequiredPosture {
	if cfg == nil {
		return RequiredPosture{PolicyVersion: policyVersion}
	}
	return RequiredPosture{
		KeyExchange:   cfg.HybridPeer,
		PolicyVersion: policyVersion,
	}
}

func BuildEvidence(required RequiredPosture, decisionID string, observed string, source string, connID string, state *tls.ConnectionState, detail string, now time.Time) VerificationEvidence {
	evidence := VerificationEvidence{
		DecisionID:        decisionID,
		Required:          required.KeyExchange,
		Observed:          observed,
		Source:            source,
		ConnectionID:      connID,
		Timestamp:         now.UTC(),
		PolicyVersion:     required.PolicyVersion,
		Details:           detail,
		Status:            Unverified,
		ApplicationAccess: AccessDenied,
	}

	if state != nil {
		evidence.TLSVersion = tls.VersionName(state.Version)
		evidence.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			evidence.CertificateSignature = state.PeerCertificates[0].SignatureAlgorithm.String()
		}
	}

	switch {
	case required.KeyExchange == "":
		evidence.Details = withFallbackDetail(detail, "required key exchange was not specified")
	case observed == "":
		evidence.Details = withFallbackDetail(detail, "negotiated key exchange could not be observed")
	case observed == required.KeyExchange:
		evidence.Status = Compliant
	case observed != required.KeyExchange:
		evidence.Status = NonCompliant
	}

	return evidence
}

func ObservedKeyExchange(state tls.ConnectionState) string {
	switch state.CurveID {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case 0:
		return ""
	default:
		return ""
	}
}

func CurveNames(ids []tls.CurveID) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, curveName(id))
	}
	return names
}

func CurveIDs(names []string) ([]tls.CurveID, error) {
	ids := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		id, err := curveID(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func curveName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	default:
		return id.String()
	}
}

func curveID(name string) (tls.CurveID, error) {
	switch name {
	case "X25519MLKEM768":
		return tls.X25519MLKEM768, nil
	case "X25519":
		return tls.X25519, nil
	default:
		return 0, fmt.Errorf("unsupported curve name: %s", name)
	}
}

func withFallbackDetail(detail string, fallback string) string {
	if detail != "" {
		return detail
	}
	return fallback
}

func ApplyAttributionResult(evidence *VerificationEvidence, result attribution.Result) {
	if evidence == nil {
		return
	}

	evidence.AttributionStatus = mapAttributionStatus(result.Status)
	evidence.AttributionDetail = result.Detail
	evidence.Workload = nil

	if result.Workload == nil {
		return
	}

	basis := string(result.AttributionBasis)
	if basis == "" && result.Workload != nil {
		basis = string(result.Workload.AttributionBasis)
	}

	evidence.Workload = &WorkloadMetadata{
		PID:                   result.Workload.PID,
		Executable:            result.Workload.Executable,
		ProcessStartTimeTicks: result.Workload.ProcessStartTimeTicks,
		SocketInode:           result.Workload.SocketInode,
		AttributionBasis:      basis,
	}
}

func mapAttributionStatus(status attribution.AttributionStatus) AttributionStatus {
	switch status {
	case attribution.Attributed:
		return Attributed
	case attribution.Unattributed:
		return Unattributed
	case attribution.Ambiguous:
		return Ambiguous
	default:
		return ""
	}
}

func (e VerificationEvidence) String() string {
	return fmt.Sprintf("decision=%s required=%s observed=%s status=%s access=%s source=%s", e.DecisionID, e.Required, e.Observed, e.Status, e.ApplicationAccess, e.Source)
}
