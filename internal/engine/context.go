// internal/engine/context.go
package engine

import (
    pb "github.com/yourorg/janus/api/proto/v1"
)

// NewContextFromProto converts a protobuf request into the internal Context struct.
func NewContextFromProto(req *pb.ContextRequest) Context {
    return Context{
        Scenario:          req.Scenario,
        Risk:              int(req.Risk),
        LatencyBudgetMs:   req.LatencyBudgetMs,
        RAMKB:             req.RamKb,
        PeerAlgorithms:    req.PeerAlgorithms,
        KeyRotationHours:  int(req.KeyRotationHours),
        CertValidityDays:  int(req.CertValidityDays),
        // NEW fields
        Region:            req.Region,
        DeviceType:        req.DeviceType,
    }
}
