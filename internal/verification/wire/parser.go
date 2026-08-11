package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	recordTypeHandshake      = 22
	handshakeTypeServerHello = 2
	extensionSupportedVer    = 43
	extensionKeyShare        = 51
)

var (
	ErrIncompleteRecord     = errors.New("incomplete tls record")
	ErrIncompleteHandshake  = errors.New("incomplete handshake message")
	ErrServerHelloNotFound  = errors.New("server hello not found")
	ErrMalformedServerHello = errors.New("malformed server hello")
)

type Observation struct {
	TLSVersion string
	GroupID    uint16
	GroupName  string
}

func ObserveServerHello(data []byte) (Observation, error) {
	var offset int
	for offset < len(data) {
		if len(data[offset:]) < 5 {
			return Observation{}, ErrIncompleteRecord
		}

		recordType := data[offset]
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		recordEnd := offset + 5 + recordLen
		if recordEnd > len(data) {
			return Observation{}, ErrIncompleteRecord
		}

		payload := data[offset+5 : recordEnd]
		if recordType == recordTypeHandshake {
			observation, found, err := parseHandshakeRecord(payload)
			if err != nil {
				return Observation{}, err
			}
			if found {
				return observation, nil
			}
		}

		offset = recordEnd
	}

	return Observation{}, ErrServerHelloNotFound
}

func parseHandshakeRecord(payload []byte) (Observation, bool, error) {
	var offset int
	for offset < len(payload) {
		if len(payload[offset:]) < 4 {
			return Observation{}, false, ErrIncompleteHandshake
		}

		handshakeType := payload[offset]
		handshakeLen := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
		messageEnd := offset + 4 + handshakeLen
		if messageEnd > len(payload) {
			return Observation{}, false, ErrIncompleteHandshake
		}

		if handshakeType == handshakeTypeServerHello {
			observation, err := parseServerHello(payload[offset+4 : messageEnd])
			if err != nil {
				return Observation{}, false, err
			}
			return observation, true, nil
		}

		offset = messageEnd
	}

	return Observation{}, false, nil
}

func parseServerHello(body []byte) (Observation, error) {
	if len(body) < 38 {
		return Observation{}, fmt.Errorf("%w: server hello too short", ErrMalformedServerHello)
	}

	offset := 0
	legacyVersion := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2
	offset += 32 // random

	if offset >= len(body) {
		return Observation{}, fmt.Errorf("%w: missing session id length", ErrMalformedServerHello)
	}
	sessionIDLen := int(body[offset])
	offset++
	if offset+sessionIDLen+2+1+2 > len(body) {
		return Observation{}, fmt.Errorf("%w: invalid session id length", ErrMalformedServerHello)
	}
	offset += sessionIDLen
	offset += 2 // cipher suite
	offset += 1 // compression method

	extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extLen > len(body) {
		return Observation{}, fmt.Errorf("%w: invalid extensions length", ErrMalformedServerHello)
	}

	extensions := body[offset : offset+extLen]
	selectedVersion := legacyVersion
	var groupID uint16
	var foundGroup bool

	for extOffset := 0; extOffset < len(extensions); {
		if len(extensions[extOffset:]) < 4 {
			return Observation{}, fmt.Errorf("%w: truncated extension header", ErrMalformedServerHello)
		}
		extType := binary.BigEndian.Uint16(extensions[extOffset : extOffset+2])
		extDataLen := int(binary.BigEndian.Uint16(extensions[extOffset+2 : extOffset+4]))
		extOffset += 4
		if extOffset+extDataLen > len(extensions) {
			return Observation{}, fmt.Errorf("%w: truncated extension payload", ErrMalformedServerHello)
		}
		extData := extensions[extOffset : extOffset+extDataLen]

		switch extType {
		case extensionSupportedVer:
			if len(extData) != 2 {
				return Observation{}, fmt.Errorf("%w: invalid supported_versions length", ErrMalformedServerHello)
			}
			selectedVersion = binary.BigEndian.Uint16(extData)
		case extensionKeyShare:
			if len(extData) < 4 {
				return Observation{}, fmt.Errorf("%w: invalid key_share extension length", ErrMalformedServerHello)
			}
			groupID = binary.BigEndian.Uint16(extData[:2])
			keyExchangeLen := int(binary.BigEndian.Uint16(extData[2:4]))
			if len(extData[4:]) != keyExchangeLen {
				return Observation{}, fmt.Errorf("%w: invalid key_share payload length", ErrMalformedServerHello)
			}
			foundGroup = true
		}

		extOffset += extDataLen
	}

	if !foundGroup {
		return Observation{}, fmt.Errorf("%w: key_share extension missing", ErrMalformedServerHello)
	}

	return Observation{
		TLSVersion: tlsVersionName(selectedVersion),
		GroupID:    groupID,
		GroupName:  groupName(groupID),
	}, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}
