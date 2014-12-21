package icmp

import (
	"encoding/binary"
	"errors"
	"io"
)

//ICMP types
const (
	EchoReply              = uint16(0 << 8)
	DestinationUnreachable = uint16(3 << 8)
	SourceQuench           = uint16(4 << 8)
	RedirectMessage        = uint16(5 << 8)
	EchoRequest            = uint16(8 << 8)
	RouterAdvertisement    = uint16(9 << 8)
	RouterSolicitation     = uint16(10 << 8)
	TimeExceeded           = uint16(11 << 8)
	ParameterProblem       = uint16(12 << 8)
	TimeStamp              = uint16(13 << 8)
	TimeStampReply         = uint16(14 << 8)
	InformationRequest     = uint16(15 << 8)
	InformationReply       = uint16(16 << 8)
	AddressMaskRequest     = uint16(17 << 8)
	AddressMaskReply       = uint16(18 << 8)
	Traceroute             = uint16(30 << 8)
)

// calculateChecksum - perform the checksum calculation of the icmp message
func calculateChecksum(im IcmpMessage) uint16 {
	// get the message byte slice
	p := im.Bytes()
	cscov := len(p) - 1
	s := uint32(0)
	// for the number of bytes pairs, add up the byte pairs
	for i := 0; i < cscov; i += 2 {
		// s is 16 bit word
		s += uint32(p[i+1])<<8 | uint32(p[i])
	}
	// get the last byte if there weren't an even number of bytes added in
	if cscov&1 == 0 {
		s += uint32(p[cscov])
	}

	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)

	// place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero
	var hi, lo byte
	hi ^= byte(^s)
	lo ^= byte(^s >> 8)
	return uint16(uint16(hi)<<8 + uint16(lo))
}

// IcmpHeader - Fields of the ICMP header
type IcmpHeader struct {
	TypeCode uint16
	Checksum uint16
}

// NewIcmpHeader - create a new icmp header
func NewIcmpHeader(tc uint16, cs uint16) IcmpHeader {
	return IcmpHeader{
		TypeCode: tc,
		Checksum: cs,
	}
}

//Write - write the EchoRequestHeader
func (ih *IcmpHeader) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, ih.TypeCode)
	if err != nil {
		return errors.New("failed to write icmp type/code")
	}
	err = binary.Write(w, binary.BigEndian, ih.Checksum)
	if err != nil {
		return errors.New("failed to write icmp checksum")
	}
	return nil
}

// IcmpMessage is an icmp message interface to implement
type IcmpMessage interface {
	Bytes() []byte
	Write(io.Writer) error
}
