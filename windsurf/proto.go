package windsurf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// Hand-rolled protobuf encoding/decoding. The Devin/Windsurf schema is small
// and stable; generated code would be overkill.

// --- encoding -----------------------------------------------------------------

func encodeVarint(v uint64) []byte {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], v)
	return buf[:n]
}

func encodeTag(field uint64, wireType byte) []byte {
	return encodeVarint(field<<3 | uint64(wireType))
}

func encodeString(field uint64, s string) []byte {
	tag := encodeTag(field, 2) // wire type 2 = length-delimited
	data := []byte(s)
	return append(append(tag, encodeVarint(uint64(len(data)))...), data...)
}

func encodeBytes(field uint64, b []byte) []byte {
	tag := encodeTag(field, 2)
	return append(append(tag, encodeVarint(uint64(len(b)))...), b...)
}

func encodeUvarint(field, v uint64) []byte {
	tag := encodeTag(field, 0) // wire type 0 = varint
	return append(tag, encodeVarint(v)...)
}

func encodeSubmsg(field uint64, data []byte) []byte {
	return encodeBytes(field, data)
}

func encodeFloat64(field uint64, v float64) []byte {
	tag := encodeTag(field, 1) // wire type 1 = 64-bit
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
	return append(tag, buf[:]...)
}

// --- decoding -----------------------------------------------------------------

type protoField struct {
	Number   uint64
	WireType byte
	Data     []byte   // for length-delimited
	Value    uint64   // for varint
	Fixed64  [8]byte  // for 64-bit
	Fixed32  [4]byte  // for 32-bit
}

func decodeFields(buf []byte) ([]protoField, error) {
	var fields []protoField
	for len(buf) > 0 {
		tag, n := binary.Uvarint(buf)
		if n <= 0 {
			return nil, errors.New("proto: bad varint in tag")
		}
		buf = buf[n:]
		wireType := byte(tag & 0x07)
		fieldNum := tag >> 3
		f := protoField{Number: fieldNum, WireType: wireType}

		switch wireType {
		case 0: // varint
			v, n := binary.Uvarint(buf)
			if n <= 0 {
				return nil, fmt.Errorf("proto: bad varint for field %d", fieldNum)
			}
			buf = buf[n:]
			f.Value = v
		case 1: // 64-bit
			if len(buf) < 8 {
				return nil, fmt.Errorf("proto: truncated fixed64 for field %d", fieldNum)
			}
			copy(f.Fixed64[:], buf[:8])
			buf = buf[8:]
		case 2: // length-delimited
			length, n := binary.Uvarint(buf)
			if n <= 0 {
				return nil, fmt.Errorf("proto: bad length for field %d", fieldNum)
			}
			buf = buf[n:]
			if uint64(len(buf)) < length {
				return nil, fmt.Errorf("proto: truncated data for field %d", fieldNum)
			}
			f.Data = buf[:length]
			buf = buf[length:]
		case 5: // 32-bit
			if len(buf) < 4 {
				return nil, fmt.Errorf("proto: truncated fixed32 for field %d", fieldNum)
			}
			copy(f.Fixed32[:], buf[:4])
			buf = buf[4:]
		default:
			return nil, fmt.Errorf("proto: unsupported wire type %d for field %d", wireType, fieldNum)
		}
		fields = append(fields, f)
	}
	return fields, nil
}

func fieldString(fields []protoField, num uint64) string {
	for _, f := range fields {
		if f.Number == num && f.WireType == 2 {
			return string(f.Data)
		}
	}
	return ""
}

func fieldUint64(fields []protoField, num uint64) uint64 {
	for _, f := range fields {
		if f.Number == num && f.WireType == 0 {
			return f.Value
		}
	}
	return 0
}

func fieldInt64(fields []protoField, num uint64) int64 {
	return int64(fieldUint64(fields, num))
}

func fieldSubmsg(fields []protoField, num uint64) []byte {
	for _, f := range fields {
		if f.Number == num && f.WireType == 2 {
			return f.Data
		}
	}
	return nil
}

func fieldBool(fields []protoField, num uint64) bool {
	return fieldUint64(fields, num) != 0
}

func fieldAllSubmsg(fields []protoField, num uint64) [][]byte {
	var result [][]byte
	for _, f := range fields {
		if f.Number == num && f.WireType == 2 {
			result = append(result, f.Data)
		}
	}
	return result
}

// --- tool schema helpers -----------------------------------------------------

func marshalToolSchema(schema map[string]any) string {
	b, err := json.Marshal(schema)
	if err != nil {
		return "{}"
	}
	return string(b)
}
