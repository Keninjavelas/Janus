package pcap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type FlowKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

type Flow struct {
	Key             FlowKey
	Segments        [][]byte
	Bytes           []byte
	ReassemblyError error
}

type tcpSegment struct {
	seq     uint32
	payload []byte
}

var (
	ErrAmbiguousTCPOverlap = errors.New("ambiguous tcp overlap")
	ErrMissingTCPData      = errors.New("missing tcp stream bytes")
)

func ReadTCPFlows(r io.Reader) ([]Flow, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open pcap reader: %w", err)
	}

	byFlow := make(map[FlowKey][]tcpSegment)
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}

		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipLayer == nil || tcpLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}

		key := FlowKey{
			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstIP:   ip.DstIP.String(),
			DstPort: uint16(tcp.DstPort),
		}
		byFlow[key] = append(byFlow[key], tcpSegment{
			seq:     tcp.Seq,
			payload: append([]byte(nil), tcp.Payload...),
		})
	}

	keys := make([]FlowKey, 0, len(byFlow))
	for key := range byFlow {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})

	flows := make([]Flow, 0, len(keys))
	for _, key := range keys {
		segments, reassemblyErr := reassembleSegments(byFlow[key])
		flow := Flow{
			Key:             key,
			Segments:        segments,
			ReassemblyError: reassemblyErr,
		}
		for _, segment := range segments {
			flow.Bytes = append(flow.Bytes, segment...)
		}
		flows = append(flows, flow)
	}

	return flows, nil
}

func reassembleSegments(segments []tcpSegment) ([][]byte, error) {
	if len(segments) == 0 {
		return nil, nil
	}

	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].seq == segments[j].seq {
			return len(segments[i].payload) > len(segments[j].payload)
		}
		return segments[i].seq < segments[j].seq
	})

	assembled := append([]byte(nil), segments[0].payload...)
	ordered := [][]byte{append([]byte(nil), segments[0].payload...)}
	baseSeq := segments[0].seq

	for _, segment := range segments[1:] {
		start := int(segment.seq - baseSeq)
		if start > len(assembled) {
			return ordered, ErrMissingTCPData
		}

		overlap := len(assembled) - start
		if overlap < 0 {
			overlap = 0
		}

		shared := overlap
		if shared > len(segment.payload) {
			shared = len(segment.payload)
		}
		if shared > 0 && !bytes.Equal(assembled[start:start+shared], segment.payload[:shared]) {
			return ordered, ErrAmbiguousTCPOverlap
		}

		if len(segment.payload) <= overlap {
			continue
		}

		tail := append([]byte(nil), segment.payload[overlap:]...)
		ordered = append(ordered, tail)
		assembled = append(assembled, tail...)
	}

	return ordered, nil
}
