package mac

import (
	"fmt"
	"net"
)

// A MAC is a physical hardware address based on the standard net.HardwareAddr.
type MAC net.HardwareAddr

// ParseMAC parses s as 12 hex digits, IEEE 802 MAC-48 or EUI-48,
// using one of the folowing formats:
//   0123456789ab
//   0123.4567.89ab
//   01-23.45.67.89ab
//   01:23:45:67:89:ab
// the EUI-64 format is not suported.
func ParseMAC(s string) (m MAC, err error) {
	if len(s) == 12 {
		s = fmt.Sprintf("%s.%s.%s", s[0:4], s[4:8], s[8:12])
	}
	hw, err := net.ParseMAC(s)
	if len(hw) == 8 {
		return nil, &net.AddrError{Err: "EUI-64 not suported", Addr: s}
	}
	return MAC(hw), err
}

// String return mac as six groups o 2 hex digits. "01:23:45:67:89:ab"
// Canonical "01-23-45-67-89-ab" not implemented
func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

// PlainString as a single group of 12 hex digits. "0123456789ab"
func (m MAC) PlainString() string {
	const hexDigit = "0123456789abcdef"
	buf := make([]byte, 0, len(m)*2)
	for _, b := range m {
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

// CiscoString as three groups of 4 hex digits. "0123.4567.89ab" (3x4)
func (m MAC) CiscoString() string {
	s := m.PlainString()
	if len(s) < 12 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s", s[0:4], s[4:8], s[8:12])
}
