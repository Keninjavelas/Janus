//go:build !linux

package attribution

import "fmt"

func ResolveLocalSourceOwner(Flow) (Result, error) {
	return Result{
		Status: Unattributed,
		Detail: "local flow attribution requires linux procfs",
	}, fmt.Errorf("local flow attribution requires linux procfs")
}
