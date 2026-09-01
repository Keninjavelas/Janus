//go:build linux && livecapture

package pcap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gopcap "github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	liveSnapLen     int32         = 65535
	livePollTimeout time.Duration = 100 * time.Millisecond
)

func InspectLiveCapture(ctx context.Context, cfg LiveCaptureConfig) (LiveCaptureResult, error) {
	if cfg.Interface == "" {
		return LiveCaptureResult{}, fmt.Errorf("live capture interface is required")
	}
	if cfg.SnapLen == 0 {
		cfg.SnapLen = liveSnapLen
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = livePollTimeout
	}

	handle, err := gopcap.OpenLive(cfg.Interface, cfg.SnapLen, cfg.Promiscuous, cfg.PollTimeout)
	if err != nil {
		return LiveCaptureResult{}, fmt.Errorf("open live capture on %s: %w", cfg.Interface, err)
	}
	defer handle.Close()

	filter := "tcp"
	if cfg.Port != 0 {
		filter = fmt.Sprintf("tcp port %d", cfg.Port)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return LiveCaptureResult{}, fmt.Errorf("apply capture filter %q: %w", filter, err)
	}

	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(uint32(cfg.SnapLen), handle.LinkType()); err != nil {
		return LiveCaptureResult{}, fmt.Errorf("write in-memory pcap header: %w", err)
	}
	if err := signalCaptureReady(); err != nil {
		return LiveCaptureResult{}, fmt.Errorf("signal capture readiness: %w", err)
	}

	packetStats := LiveCaptureDiagnostics{}
	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == gopcap.NextErrorTimeoutExpired {
				result, inspectErr := InspectCaptureDetailed(bytes.NewReader(capture.Bytes()), cfg.Port)
				if inspectErr != nil {
					return LiveCaptureResult{}, inspectErr
				}
				result.Diagnostics.Merge(packetStats)
				select {
				case <-ctx.Done():
					return result, nil
				default:
					continue
				}
			}
			return LiveCaptureResult{}, fmt.Errorf("read live packet: %w", err)
		}

		packetStats.PacketsSeen++
		packetStats.CaptureLength += ci.CaptureLength
		packetStats.WireLength += ci.Length
		if ci.CaptureLength < ci.Length {
			packetStats.TruncatedPackets++
		}

		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.NoCopy)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			packetStats.TCPPacketsSeen++
			if cfg.OnTCPPacket != nil {
				tcp := tcpLayer.(*layers.TCP)
				payloadLen := len(tcp.Payload)
				if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
					ip4 := ip4Layer.(*layers.IPv4)
					cfg.OnTCPPacket(ip4.SrcIP.String(), uint16(tcp.SrcPort), ip4.DstIP.String(), uint16(tcp.DstPort), payloadLen)
				} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
					ip6 := ip6Layer.(*layers.IPv6)
					cfg.OnTCPPacket(ip6.SrcIP.String(), uint16(tcp.SrcPort), ip6.DstIP.String(), uint16(tcp.DstPort), payloadLen)
				}
			}
		}

		if err := writer.WritePacket(ci, data); err != nil {
			return LiveCaptureResult{}, fmt.Errorf("append captured packet: %w", err)
		}

		result, err := InspectCaptureDetailed(bytes.NewReader(capture.Bytes()), cfg.Port)
		if err != nil {
			return LiveCaptureResult{}, err
		}
		result.Diagnostics.Merge(packetStats)
		if hasObservedServerFlow(result.Inspections, cfg.Port) {
			return result, nil
		}

		select {
		case <-ctx.Done():
			return result, nil
		default:
		}
	}
}

func hasObservedServerFlow(inspections []FlowInspection, port uint16) bool {
	if port == 0 {
		for _, inspection := range inspections {
			if inspection.Status == StatusObserved {
				return true
			}
		}
		return false
	}

	for _, inspection := range inspections {
		if inspection.Flow.SrcPort == port && inspection.Status == StatusObserved {
			return true
		}
	}
	return false
}

func signalCaptureReady() error {
	readyPath := os.Getenv("JANUS_WIRE_READY_FILE")
	if readyPath == "" {
		return nil
	}
	return os.WriteFile(readyPath, []byte("JANUS_WIRE_READY\n"), 0600)
}
