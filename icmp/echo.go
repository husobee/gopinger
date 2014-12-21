package icmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

const (
	EchoReplyCode   = uint16(0)
	EchoRequestCode = uint16(0)
)

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
func NewEchoHeader(tc uint16, id, seq uint16) EchoHeader {
	icmpHeader := NewIcmpHeader(tc, 0)
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
			Header:  NewEchoHeader(EchoRequest+EchoRequestCode, id, seq),
			Payload: payload,
		},
	}
	// calculate the checksum of the message before returning
	request.CalculateChecksum()
	return request
}

// EchoReplyMessage - wraps the EchoMessage
type EchoReplyMessage struct {
	*EchoMessage
}

// NewEchoReplyMessage - setup an echo response message
func NewEchoReplyMessage(id, seq uint16, payload []byte) EchoReplyMessage {
	response := EchoReplyMessage{
		&EchoMessage{
			Header:  NewEchoHeader(EchoReply+EchoReplyCode, id, seq),
			Payload: payload,
		},
	}
	// calculate checksum
	response.CalculateChecksum()
	return response
}
