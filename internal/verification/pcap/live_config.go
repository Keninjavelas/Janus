package pcap

import (
	"fmt"
	"time"
)

type LiveCaptureConfig struct {
	Interface   string
	Port        uint16
	SnapLen     int32
	Promiscuous bool
	PollTimeout time.Duration
	OnTCPPacket func(srcIP string, srcPort uint16, dstIP string, dstPort uint16)
}

type LiveCaptureDiagnostics struct {
	PacketsSeen           int
	TCPPacketsSeen        int
	FlowsSeen             int
	CaptureLength         int
	WireLength            int
	TruncatedPackets      int
	ServerPayloadBytes    int
	ReassemblyGap         int
	ReassemblyConflict    int
	TLSRecordsSeen        int
	ServerHelloCandidates int
}

type LiveCaptureResult struct {
	Inspections []FlowInspection
	Diagnostics LiveCaptureDiagnostics
}

func (d *LiveCaptureDiagnostics) Merge(other LiveCaptureDiagnostics) {
	d.PacketsSeen += other.PacketsSeen
	d.TCPPacketsSeen += other.TCPPacketsSeen
	d.FlowsSeen += other.FlowsSeen
	d.CaptureLength += other.CaptureLength
	d.WireLength += other.WireLength
	d.TruncatedPackets += other.TruncatedPackets
	d.ServerPayloadBytes += other.ServerPayloadBytes
	d.ReassemblyGap += other.ReassemblyGap
	d.ReassemblyConflict += other.ReassemblyConflict
	d.TLSRecordsSeen += other.TLSRecordsSeen
	d.ServerHelloCandidates += other.ServerHelloCandidates
}

func (d LiveCaptureDiagnostics) String() string {
	return fmt.Sprintf(
		"packets_seen=%d tcp_packets_seen=%d flows_seen=%d capture_length=%d wire_length=%d truncated_packets=%d server_payload_bytes=%d reassembly_gap=%d reassembly_conflict=%d tls_records_seen=%d server_hello_candidates=%d",
		d.PacketsSeen,
		d.TCPPacketsSeen,
		d.FlowsSeen,
		d.CaptureLength,
		d.WireLength,
		d.TruncatedPackets,
		d.ServerPayloadBytes,
		d.ReassemblyGap,
		d.ReassemblyConflict,
		d.TLSRecordsSeen,
		d.ServerHelloCandidates,
	)
}
