package wire

import "fmt"

const (
	groupX25519         uint16 = 0x001D
	groupX25519MLKEM768 uint16 = 0x11EC
)

func groupName(id uint16) string {
	switch id {
	case groupX25519:
		return "X25519"
	case groupX25519MLKEM768:
		return "X25519MLKEM768"
	default:
		return fmt.Sprintf("UNKNOWN_0x%04X", id)
	}
}
