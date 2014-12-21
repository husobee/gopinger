package icmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

const (
	// EchoRequestType is 8
	EchoRequestType = byte(8)
	//EchoRequestCode is 0
	EchoRequestCode = byte(0)
	// EchoResponseType is 0
	EchoResponseType = byte(0)
	//EchoResponseCode is 0
	EchoResponseCode = byte(0)
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

// Echo Header (echo request/response header)
type EchoHeader struct {
	Header   IcmpHeader
	Id       uint16
	Sequence uint16
}

//Write - write the EchoHeader
func (eh *EchoHeader) Write(w io.Writer) error {
	// write the icmp header
	err := eh.Header.Write(w)
	if err != nil {
		return errors.New("failed to write icmp header")
	}
	// write the echo ident
	err = binary.Write(w, binary.BigEndian, eh.Id)
	if err != nil {
		return errors.New("failed to write echo request/response ident")
	}
	// write the echo sequence
	err = binary.Write(w, binary.BigEndian, eh.Sequence)
	if err != nil {
		return errors.New("failed to write echo request/response seq")
	}
	return nil
}

// NewEchoHeader - Create a new echo header, specify the type/code/id/seq
func NewEchoHeader(t, c byte, id, seq uint16) EchoHeader {
	icmpHeader := NewIcmpHeader(t, c, 0)
	return EchoHeader{
		Header:   icmpHeader,
		Id:       id,
		Sequence: seq,
	}
}

// EchoMessage - Base type for echo request/reply
type EchoMessage struct {
	Header  EchoHeader
	Payload []byte
}

//Write - write the EchoMessage to an io.writer
func (em *EchoMessage) Write(w io.Writer) error {
	// write the echoheader
	err := em.Header.Write(w)
	if err != nil {
		return errors.New("failed to write echo header")
	}
	// write the payload
	err = binary.Write(w, binary.BigEndian, em.Payload)
	if err != nil {
		return errors.New("failed to write echo payload")
	}
	return nil
}

//CalculateChecksum - wrapper around calculateChecksum, sets the checksum
func (em *EchoMessage) CalculateChecksum() {
	em.Header.Header.Checksum = calculateChecksum(em)
}

// Bytes - Get the byte repr of the echo message
func (em *EchoMessage) Bytes() []byte {
	var buffer = new(bytes.Buffer)
	em.Write(buffer)
	return buffer.Bytes()
}

// Bytes - Get the byte repr of the echo message
func (em *EchoMessage) StdOut() {
	em.Write(os.Stdout)
}

// EchoRequestMessage - wraps the EchoMessage, type 8, code 0
type EchoRequestMessage struct {
	*EchoMessage
}

// NewEchoRequestMessage - create a new echo request message
func NewEchoRequestMessage(id, seq uint16, payload []byte) EchoRequestMessage {
	request := EchoRequestMessage{
		&EchoMessage{
			Header:  NewEchoHeader(EchoRequestType, EchoRequestCode, id, seq),
			Payload: payload,
		},
	}
	// calculate the checksum of the message before returning
	request.CalculateChecksum()
	return request
}

// EchoResponseMessage - wraps the EchoMessage
type EchoResponseMessage struct {
	*EchoMessage
}

// NewEchoResponseMessage - setup an echo response message
func NewEchoResponseMessage(id, seq uint16, payload []byte) EchoResponseMessage {
	response := EchoResponseMessage{
		&EchoMessage{
			Header:  NewEchoHeader(EchoResponseType, EchoResponseCode, id, seq),
			Payload: payload,
		},
	}
	// calculate checksum
	response.CalculateChecksum()
	return response
}

// IcmpHeader - Fields of the ICMP header
type IcmpHeader struct {
	Type     byte
	Code     byte
	Checksum uint16
}

// NewIcmpHeader - create a new icmp header
func NewIcmpHeader(t, c byte, cs uint16) IcmpHeader {
	return IcmpHeader{
		Type:     t,
		Code:     c,
		Checksum: cs,
	}
}

//Write - write the EchoRequestHeader
func (ih *IcmpHeader) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, ih.Type)
	if err != nil {
		return errors.New("failed to write icmp type")
	}
	err = binary.Write(w, binary.BigEndian, ih.Code)
	if err != nil {
		return errors.New("failed to write icmp code")
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
