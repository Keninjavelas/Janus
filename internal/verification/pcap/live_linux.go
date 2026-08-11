//go:build linux && livecapture

package pcap

import (
	"bytes"
	"context"
	"fmt"
	"time"

	gopcap "github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func InspectLiveCapture(ctx context.Context, cfg LiveCaptureConfig) ([]FlowInspection, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("live capture interface is required")
	}
	if cfg.SnapLen == 0 {
		cfg.SnapLen = 65535
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = 250 * time.Millisecond
	}

	handle, err := gopcap.OpenLive(cfg.Interface, cfg.SnapLen, cfg.Promiscuous, cfg.PollTimeout)
	if err != nil {
		return nil, fmt.Errorf("open live capture on %s: %w", cfg.Interface, err)
	}
	defer handle.Close()

	filter := "tcp"
	if cfg.Port != 0 {
		filter = fmt.Sprintf("tcp port %d", cfg.Port)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("apply capture filter %q: %w", filter, err)
	}

	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(uint32(cfg.SnapLen), handle.LinkType()); err != nil {
		return nil, fmt.Errorf("write in-memory pcap header: %w", err)
	}

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == gopcap.NextErrorTimeoutExpired {
				select {
				case <-ctx.Done():
					return InspectCapture(bytes.NewReader(capture.Bytes()))
				default:
					continue
				}
			}
			return nil, fmt.Errorf("read live packet: %w", err)
		}

		if err := writer.WritePacket(ci, data); err != nil {
			return nil, fmt.Errorf("append captured packet: %w", err)
		}

		inspections, err := InspectCapture(bytes.NewReader(capture.Bytes()))
		if err != nil {
			return nil, err
		}
		if hasTerminalServerFlow(inspections, cfg.Port) {
			return inspections, nil
		}

		select {
		case <-ctx.Done():
			return inspections, nil
		default:
		}
	}
}

func hasTerminalServerFlow(inspections []FlowInspection, port uint16) bool {
	if port == 0 {
		for _, inspection := range inspections {
			if inspection.Status != StatusIgnored {
				return true
			}
		}
		return false
	}

	for _, inspection := range inspections {
		if inspection.Flow.SrcPort == port && inspection.Status != StatusIgnored {
			return true
		}
	}
	return false
}
