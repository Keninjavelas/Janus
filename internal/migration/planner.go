package migration

import (
	"strings"
	"time"

	"github.com/yourorg/janus/internal/discovery"
	"github.com/yourorg/janus/internal/risk"
	"github.com/yourorg/janus/internal/verification"
)

type Status string
type Mode string
type VerificationState string

const (
	StatusNotStarted Status = "NOT_STARTED"
	StatusPlanned    Status = "PLANNED"
	StatusCanary     Status = "CANARY"
	StatusMigrating  Status = "MIGRATING"
	StatusVerified   Status = "VERIFIED"
	StatusBlocked    Status = "BLOCKED"
	StatusRolledBack Status = "ROLLED_BACK"

	ModeAudit   Mode = "AUDIT"
	ModeWarn    Mode = "WARN"
	ModeEnforce Mode = "ENFORCE"

	VerificationPending    VerificationState = "PENDING"
	VerificationSuccessful VerificationState = "VERIFIED"
	VerificationFailed     VerificationState = "NOT_VERIFIED"
)

type Plan struct {
	AssetID            string              `json:"asset_id"`
	Service            string              `json:"service"`
	Current            string              `json:"current"`
	Target             string              `json:"target"`
	Risk               risk.Classification `json:"risk"`
	Priority           risk.Priority       `json:"priority"`
	Status             Status              `json:"status"`
	Mode               Mode                `json:"mode"`
	Blockers           []string            `json:"blockers,omitempty"`
	Reasons            []string            `json:"reasons,omitempty"`
	VerificationState  VerificationState   `json:"verification_state"`
	LastVerifiedAt     *time.Time          `json:"last_verified_at,omitempty"`
	LastVerificationID string              `json:"last_verification_id,omitempty"`
}

func BuildPlan(asset discovery.CryptoAsset, assessment risk.Assessment, blockers []string, mode Mode) Plan {
	target := asset.KeyExchange
	if target == "" || target == "UNKNOWN" || !asset.QuantumSafe {
		target = "X25519MLKEM768"
	}

	status := StatusPlanned
	if len(blockers) > 0 {
		status = StatusBlocked
	}
	if asset.KeyExchange == target && asset.CryptoStatus == string(verification.Compliant) {
		status = StatusVerified
	}

	return Plan{
		AssetID:           asset.ID,
		Service:           asset.Host,
		Current:           asset.KeyExchange,
		Target:            target,
		Risk:              assessment.Risk,
		Priority:          assessment.Priority,
		Status:            status,
		Mode:              mode,
		Blockers:          blockers,
		Reasons:           assessment.Reasons,
		VerificationState: VerificationPending,
	}
}

func VerifyPlan(plan Plan, evidence verification.VerificationEvidence) Plan {
	now := evidence.Timestamp.UTC()
	plan.LastVerifiedAt = &now
	plan.LastVerificationID = evidence.ConnectionID

	if strings.TrimSpace(evidence.Observed) == plan.Target &&
		evidence.Status == verification.Compliant &&
		evidence.Required == plan.Target {
		plan.VerificationState = VerificationSuccessful
		plan.Status = StatusVerified
		return plan
	}

	plan.VerificationState = VerificationFailed
	if plan.Status == StatusVerified {
		plan.Status = StatusMigrating
	}
	return plan
}
