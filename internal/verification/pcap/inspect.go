package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/yourorg/janus/internal/verification/wire"
)

type InspectionStatus string

const (
	StatusObserved   InspectionStatus = "OBSERVED"
	StatusUnverified InspectionStatus = "UNVERIFIED"
	StatusIgnored    InspectionStatus = "IGNORED"
)

type FlowInspection struct {
	Flow        FlowKey
	Status      InspectionStatus
	Observation *wire.Observation
	Detail      string
}

func InspectCapture(r io.Reader) ([]FlowInspection, error) {
	flows, err := ReadTCPFlows(r)
	if err != nil {
		return nil, err
	}

	inspections := make([]FlowInspection, 0, len(flows))
	for _, flow := range flows {
		inspections = append(inspections, inspectFlow(flow))
	}
	return inspections, nil
}

func inspectFlow(flow Flow) FlowInspection {
	if flow.ReassemblyError != nil {
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusUnverified,
			Detail: flow.ReassemblyError.Error(),
		}
	}

	if len(flow.Bytes) == 0 {
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusIgnored,
			Detail: "tcp flow contained no payload",
		}
	}

	var observer wire.StreamObserver
	for _, segment := range flow.Segments {
		observation, err := observer.Feed(segment)
		if err != nil {
			return FlowInspection{
				Flow:   flow.Key,
				Status: StatusUnverified,
				Detail: err.Error(),
			}
		}
		if observation != nil {
			return FlowInspection{
				Flow:        flow.Key,
				Status:      StatusObserved,
				Observation: observation,
				Detail:      fmt.Sprintf("observed %s from wire data", observation.GroupName),
			}
		}
	}

	observation, err := wire.ObserveServerHello(flow.Bytes)
	switch {
	case err == nil:
		return FlowInspection{
			Flow:        flow.Key,
			Status:      StatusObserved,
			Observation: &observation,
			Detail:      fmt.Sprintf("observed %s from reassembled wire data", observation.GroupName),
		}
	case errors.Is(err, wire.ErrServerHelloNotFound):
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusIgnored,
			Detail: "tcp flow did not contain a tls server hello",
		}
	case !looksLikeTLS(flow.Bytes):
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusIgnored,
			Detail: "tcp flow did not look like tls traffic",
		}
	case errors.Is(err, wire.ErrIncompleteRecord), errors.Is(err, wire.ErrIncompleteHandshake), errors.Is(err, wire.ErrMalformedServerHello):
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusUnverified,
			Detail: err.Error(),
		}
	default:
		return FlowInspection{
			Flow:   flow.Key,
			Status: StatusUnverified,
			Detail: err.Error(),
		}
	}
}

func looksLikeTLS(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	switch data[0] {
	case 20, 21, 22, 23:
	default:
		return false
	}

	version := binary.BigEndian.Uint16(data[1:3])
	return version == 0x0301 || version == 0x0302 || version == 0x0303 || version == 0x0304
}
