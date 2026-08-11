//go:build !envoy

package envoy

import (
	"fmt"
	"time"
)

func StartAuthServer(string) error {
	return fmt.Errorf("envoy support is not enabled; rebuild with -tags=envoy")
}

func ShutdownAuthServer(time.Duration) {}
