package icmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	TimeStampCode      = uint16(0)
	TimeStampReplyCode = uint16(0)
)

// TimeStampMessage - Base type for echo request/reply
type TimeStampMessage struct {
	Header             TimeStampHeader
	OriginateTimestamp uint32
	ReceiveTimestamp   uint32
	TransmitTimestamp  uint32
}

//Write - write the EchoMessage to an io.writer
func (tsm *TimeStampMessage) Write(w io.Writer) error {
	// write the timestampheader
	err := tsm.Header.Write(w)
	if err != nil {
		return errors.New("failed to write timestamp header")
	}
	err = binary.Write(w, binary.BigEndian, tsm.OriginateTimestamp)
	if err != nil {
		return errors.New("failed to write originate timestamp")
	}
	err = binary.Write(w, binary.BigEndian, tsm.ReceiveTimestamp)
	if err != nil {
		return errors.New("failed to write receive timestamp")
	}
	err = binary.Write(w, binary.BigEndian, tsm.TransmitTimestamp)
	if err != nil {
		return errors.New("failed to write transmit timestamp")
	}
	return nil

}

//CalculateChecksum - wrapper around calculateChecksum, sets the checksum
func (tsm *TimeStampMessage) CalculateChecksum() {
	tsm.Header.Header.Checksum = calculateChecksum(tsm)
}

// Bytes - Get the byte repr of the echo message
func (tsm *TimeStampMessage) Bytes() []byte {
	var buffer = new(bytes.Buffer)
	tsm.Write(buffer)
	return buffer.Bytes()
}

// TimeStampHeader (timestamp request/response header)
type TimeStampHeader struct {
	Header   IcmpHeader
	Id       uint16
	Sequence uint16
}

// NewTimeStampHeader - Create a new timestamp header, specify the type/code/id/seq
func NewTimeStampHeader(tc uint16, id, seq uint16) TimeStampHeader {
	icmpHeader := NewIcmpHeader(tc, 0)
	return TimeStampHeader{
		Header:   icmpHeader,
		Id:       id,
		Sequence: seq,
	}
}

//Write - write the TimeStampHeader
func (tsh *TimeStampHeader) Write(w io.Writer) error {
	// write the icmp header
	err := tsh.Header.Write(w)
	if err != nil {
		return errors.New("failed to write icmp header")
	}
	// write the echo ident
	err = binary.Write(w, binary.BigEndian, tsh.Id)
	if err != nil {
		return errors.New("failed to write echo request/response ident")
	}
	// write the echo sequence
	err = binary.Write(w, binary.BigEndian, tsh.Sequence)
	if err != nil {
		return errors.New("failed to write echo request/response seq")
	}
	return nil
}

type TimeStampRequestMessage struct {
	*TimeStampMessage
}

// NewTimeStampRequestMessage - create a new timestamp request message
func NewTimeStampRequestMessage(id, seq uint16, orig, rec, trans uint32) TimeStampRequestMessage {
	request := TimeStampRequestMessage{
		&TimeStampMessage{
			Header:             NewTimeStampHeader(TimeStamp+TimeStampCode, id, seq),
			OriginateTimestamp: orig,
			ReceiveTimestamp:   rec,
			TransmitTimestamp:  trans,
		},
	}
	// calculate the checksum of the message before returning
	request.CalculateChecksum()
	return request
}

type TimeStampReplyMessage struct {
	*TimeStampMessage
}

// NewTimeStampReplyMessage - create a new timestamp request message
func NewTimeStampReplyMessage(id, seq uint16, orig, rec, trans uint32) TimeStampReplyMessage {
	request := TimeStampReplyMessage{
		&TimeStampMessage{
			Header:             NewTimeStampHeader(TimeStampReply+TimeStampReplyCode, id, seq),
			OriginateTimestamp: orig,
			ReceiveTimestamp:   rec,
			TransmitTimestamp:  trans,
		},
	}
	// calculate the checksum of the message before returning
	request.CalculateChecksum()
	return request
}
