//go:build linux

package nftnetlink

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderLength    = 16
	NFGenLength     = 4
	AttributeHeader = 4
	alignment       = 4

	SubsystemNFTables uint16 = 10
	TypeBatchBegin    uint16 = 0x10
	TypeBatchEnd      uint16 = 0x11

	FlagRequest   uint16 = 0x0001
	FlagMulti     uint16 = 0x0002
	FlagAck       uint16 = 0x0004
	FlagEcho      uint16 = 0x0008
	FlagRoot      uint16 = 0x0100
	FlagMatch     uint16 = 0x0200
	FlagDump             = FlagRoot | FlagMatch
	FlagReplace   uint16 = 0x0100
	FlagExclusive uint16 = 0x0200
	FlagCreate    uint16 = 0x0400

	FamilyUnspecified uint8 = 0
	FamilyIPv4        uint8 = 2
	FamilyIPv6        uint8 = 10

	NFNetlinkVersion uint8 = 0
)

type MessageOperation uint8

const (
	MessageNewTable MessageOperation = iota
	MessageGetTable
	MessageDeleteTable
	MessageNewChain
	MessageGetChain
	MessageDeleteChain
	MessageNewRule
	MessageGetRule
	MessageDeleteRule
	MessageNewSet
	MessageGetSet
	MessageDeleteSet
	MessageNewSetElement
	MessageGetSetElement
	MessageDeleteSetElement
)

var (
	ErrMalformedMessage   = errors.New("malformed netlink message")
	ErrMalformedAttribute = errors.New("malformed netlink attribute")
	ErrTransportMissing   = errors.New("raw netlink transport is required")
)

type Header struct {
	Type  uint16
	Flags uint16
	Seq   uint32
	PID   uint32
}

type Attribute struct {
	Type uint16
	Data []byte
}

type Message struct {
	Header     Header
	Family     uint8
	Version    uint8
	ResourceID uint16
	Attributes []Attribute
}

func NFTablesType(operation MessageOperation) uint16 {
	return SubsystemNFTables<<8 | uint16(operation)
}

func BatchBegin(sequence uint32) Message {
	return Message{Header: Header{Type: TypeBatchBegin, Flags: FlagRequest, Seq: sequence}, ResourceID: SubsystemNFTables}
}

func BatchEnd(sequence uint32) Message {
	return Message{Header: Header{Type: TypeBatchEnd, Flags: FlagRequest, Seq: sequence}, ResourceID: SubsystemNFTables}
}

func Encode(message Message) ([]byte, error) {
	attributeBytes, err := encodeAttributes(message.Attributes)
	if err != nil {
		return nil, err
	}
	length := HeaderLength + NFGenLength + len(attributeBytes)
	if length > int(^uint32(0)) {
		return nil, fmt.Errorf("%w: message too large", ErrMalformedMessage)
	}
	encoded := make([]byte, align(length))
	binary.NativeEndian.PutUint32(encoded[0:4], uint32(length))
	binary.NativeEndian.PutUint16(encoded[4:6], message.Header.Type)
	binary.NativeEndian.PutUint16(encoded[6:8], message.Header.Flags)
	binary.NativeEndian.PutUint32(encoded[8:12], message.Header.Seq)
	binary.NativeEndian.PutUint32(encoded[12:16], message.Header.PID)
	encoded[16] = message.Family
	encoded[17] = message.Version
	binary.BigEndian.PutUint16(encoded[18:20], message.ResourceID)
	copy(encoded[20:], attributeBytes)
	return encoded, nil
}

func Decode(frame []byte) (Message, error) {
	if len(frame) < HeaderLength+NFGenLength {
		return Message{}, fmt.Errorf("%w: shorter than nfnetlink header", ErrMalformedMessage)
	}
	length := int(binary.NativeEndian.Uint32(frame[0:4]))
	if length < HeaderLength+NFGenLength || length > len(frame) {
		return Message{}, fmt.Errorf("%w: invalid length %d", ErrMalformedMessage, length)
	}
	if align(length) != len(frame) {
		return Message{}, fmt.Errorf("%w: frame length does not match aligned message length", ErrMalformedMessage)
	}
	attributes, err := decodeAttributes(frame[HeaderLength+NFGenLength : length])
	if err != nil {
		return Message{}, err
	}
	return Message{
		Header: Header{
			Type: binary.NativeEndian.Uint16(frame[4:6]), Flags: binary.NativeEndian.Uint16(frame[6:8]),
			Seq: binary.NativeEndian.Uint32(frame[8:12]), PID: binary.NativeEndian.Uint32(frame[12:16]),
		},
		Family: frame[16], Version: frame[17], ResourceID: binary.BigEndian.Uint16(frame[18:20]),
		Attributes: attributes,
	}, nil
}

func DecodeMany(data []byte) ([]Message, error) {
	messages := make([]Message, 0)
	for len(data) > 0 {
		if len(data) < HeaderLength {
			return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedMessage)
		}
		length := int(binary.NativeEndian.Uint32(data[0:4]))
		if length < HeaderLength+NFGenLength || length > len(data) {
			return nil, fmt.Errorf("%w: invalid message length %d", ErrMalformedMessage, length)
		}
		space := align(length)
		if space > len(data) {
			return nil, fmt.Errorf("%w: truncated aligned message", ErrMalformedMessage)
		}
		message, err := Decode(data[:space])
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
		data = data[space:]
	}
	return messages, nil
}

func encodeAttributes(attributes []Attribute) ([]byte, error) {
	length := 0
	for _, attribute := range attributes {
		attributeLength := AttributeHeader + len(attribute.Data)
		if attributeLength > int(^uint16(0)) {
			return nil, fmt.Errorf("%w: attribute too large", ErrMalformedAttribute)
		}
		length += align(attributeLength)
	}
	encoded := make([]byte, length)
	offset := 0
	for _, attribute := range attributes {
		attributeLength := AttributeHeader + len(attribute.Data)
		binary.NativeEndian.PutUint16(encoded[offset:offset+2], uint16(attributeLength))
		binary.NativeEndian.PutUint16(encoded[offset+2:offset+4], attribute.Type)
		copy(encoded[offset+4:offset+attributeLength], attribute.Data)
		offset += align(attributeLength)
	}
	return encoded, nil
}

func decodeAttributes(data []byte) ([]Attribute, error) {
	attributes := make([]Attribute, 0)
	for len(data) > 0 {
		if len(data) < AttributeHeader {
			return nil, fmt.Errorf("%w: truncated header", ErrMalformedAttribute)
		}
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		if length < AttributeHeader || length > len(data) {
			return nil, fmt.Errorf("%w: invalid length %d", ErrMalformedAttribute, length)
		}
		space := align(length)
		if space > len(data) {
			return nil, fmt.Errorf("%w: truncated aligned attribute", ErrMalformedAttribute)
		}
		attributes = append(attributes, Attribute{
			Type: binary.NativeEndian.Uint16(data[2:4]),
			Data: append([]byte(nil), data[4:length]...),
		})
		data = data[space:]
	}
	return attributes, nil
}

func align(length int) int {
	return (length + alignment - 1) &^ (alignment - 1)
}
