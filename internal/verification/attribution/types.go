package attribution

import "path/filepath"

type AttributionStatus string

const (
	Attributed   AttributionStatus = "ATTRIBUTED"
	Unattributed AttributionStatus = "UNATTRIBUTED"
	Ambiguous    AttributionStatus = "AMBIGUOUS"
)

type Flow struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type Workload struct {
	PID                   int
	Executable            string
	ProcessStartTimeTicks uint64
	SocketInode           string
}

type Result struct {
	Status   AttributionStatus
	Workload *Workload
	Detail   string
}

func executableName(target string) string {
	if target == "" {
		return ""
	}
	return filepath.Base(target)
}
