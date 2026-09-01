package attribution

import "path/filepath"

type AttributionStatus string

const (
	Attributed   AttributionStatus = "ATTRIBUTED"
	Unattributed AttributionStatus = "UNATTRIBUTED"
	Ambiguous    AttributionStatus = "AMBIGUOUS"
)

// Flow defines an observed TCP 4-tuple.
// Note: For WIRE_LIVE target verification, workload attribution refers to the
// local process owning the configured target/server endpoint, not whichever
// endpoint transmitted the first observed packet.
type Flow struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// Workload represents the provenance of a local process attached to a network socket.
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
