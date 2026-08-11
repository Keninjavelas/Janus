//go:build !linux || !livecapture

package pcap

import (
	"context"
	"fmt"
)

func InspectLiveCapture(context.Context, LiveCaptureConfig) (LiveCaptureResult, error) {
	return LiveCaptureResult{}, fmt.Errorf("live capture requires linux with the livecapture build tag")
}
