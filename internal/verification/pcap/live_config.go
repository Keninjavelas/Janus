package pcap

import "time"

type LiveCaptureConfig struct {
	Interface   string
	Port        uint16
	SnapLen     int32
	Promiscuous bool
	PollTimeout time.Duration
}
