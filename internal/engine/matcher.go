// internal/engine/matcher.go
package engine

import (
    "github.com/yourorg/janus/internal/config"
    "time"
)

type Context struct {
    Scenario          string
    Risk              int
    LatencyBudgetMs   float64
    RAMKB             int64
    PeerAlgorithms    []string
    KeyRotationHours  int
    CertValidityDays  int
    // NEW fields
    Region            string
    DeviceType        string
}

// matches checks if a rule's MatchCond satisfies the given context.
func matches(cond config.MatchCond, ctx Context) bool {
    if cond.Scenario != "" && cond.Scenario != ctx.Scenario {
        return false
    }
    if cond.RiskMin != nil && ctx.Risk < *cond.RiskMin {
        return false
    }
    if cond.RiskMax != nil && ctx.Risk > *cond.RiskMax {
        return false
    }
    if cond.MaxLatencyBudgetMs != nil && ctx.LatencyBudgetMs > *cond.MaxLatencyBudgetMs {
        return false
    }
    if cond.MinRamKb != nil && ctx.RAMKB < *cond.MinRamKb {
        return false
    }
    if cond.RotationHoursMin != nil && ctx.KeyRotationHours < *cond.RotationHoursMin {
        return false
    }
    if cond.RotationHoursMax != nil && ctx.KeyRotationHours > *cond.RotationHoursMax {
        return false
    }
    if cond.CertValidityDaysMin != nil && ctx.CertValidityDays < *cond.CertValidityDaysMin {
        return false
    }
    if cond.CertValidityDaysMax != nil && ctx.CertValidityDays > *cond.CertValidityDaysMax {
        return false
    }
    // NEW Region match
    if cond.Region != "" && cond.Region != ctx.Region {
        return false
    }
    // NEW Device Type match
    if cond.DeviceType != "" && cond.DeviceType != ctx.DeviceType {
        return false
    }
    // NEW Time-of-day match
    if cond.TimeFrom != "" && cond.TimeTo != "" {
        now := time.Now()
        from, err1 := time.Parse("15:04", cond.TimeFrom)
        to, err2 := time.Parse("15:04", cond.TimeTo)
        if err1 == nil && err2 == nil {
            current := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)
            from = time.Date(0, 1, 1, from.Hour(), from.Minute(), 0, 0, time.UTC)
            to = time.Date(0, 1, 1, to.Hour(), to.Minute(), 0, 0, time.UTC)
            if from.Before(to) || from.Equal(to) {
                if current.Before(from) || current.After(to) {
                    return false
                }
            } else {
                // crosses midnight
                if !(current.After(from) || current.Before(to)) {
                    return false
                }
            }
        }
    }
    if len(cond.PeerAlgorithmsContains) > 0 {
        found := false
        for _, need := range cond.PeerAlgorithmsContains {
            for _, have := range ctx.PeerAlgorithms {
                if need == have {
                    found = true
                    break
                }
            }
            if !found {
                return false
            }
        }
    }
    return true
}

func Matches(cond config.MatchCond, ctx Context) bool {
    return matches(cond, ctx)
}
