package geomatch

import (
	"encoding/binary"
	"errors"
	"math"
)

// errProto reports a malformed protobuf message in a geodata file.
var errProto = errors.New("geomatch: malformed geodata record")

// Protobuf wire types used by the geodata formats.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

// protoReader walks the fields of one protobuf message. It supports the
// wire types of proto3 and rejects groups.
type protoReader struct {
	b   []byte
	err error
}

// next reads the next field's number and wire type. It reports false at the
// end of the message or after an error.
func (r *protoReader) next() (num uint64, typ int, ok bool) {
	if r.err != nil || len(r.b) == 0 {
		return 0, 0, false
	}
	tag, n := binary.Uvarint(r.b)
	if n <= 0 || tag>>3 == 0 {
		r.err = errProto
		return 0, 0, false
	}
	r.b = r.b[n:]
	return tag >> 3, int(tag & 7), true
}

// varint reads a varint field value.
func (r *protoReader) varint() uint64 {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errProto
		return 0
	}
	r.b = r.b[n:]
	return v
}

// bytes reads a length-delimited field value, which aliases the message.
func (r *protoReader) bytes() []byte {
	size, n := binary.Uvarint(r.b)
	if n <= 0 || size > uint64(len(r.b)-n) {
		r.err = errProto
		return nil
	}
	v := r.b[n : n+int(size)]
	r.b = r.b[n+int(size):]
	return v
}

// skip skips a field value of wire type typ.
func (r *protoReader) skip(typ int) {
	switch typ {
	case wireVarint:
		r.varint()
	case wireBytes:
		r.bytes()
	case wireI64, wireI32:
		size := 8
		if typ == wireI32 {
			size = 4
		}
		if len(r.b) < size {
			r.err = errProto
			return
		}
		r.b = r.b[size:]
	default:
		r.err = errProto
	}
}

// fieldBytes returns the first length-delimited field num of msg, if any.
func fieldBytes(msg []byte, num uint64) ([]byte, bool) {
	r := protoReader{b: msg}
	for {
		n, typ, ok := r.next()
		if !ok {
			return nil, false
		}
		if n == num && typ == wireBytes {
			v := r.bytes()
			return v, r.err == nil
		}
		r.skip(typ)
	}
}

// appendVarint and the helpers below encode messages for tests and tools.
func appendVarint(b []byte, v uint64) []byte {
	return binary.AppendUvarint(b, v)
}

func appendTag(b []byte, num uint64, typ int) []byte {
	return appendVarint(b, num<<3|uint64(typ))
}

func appendBytesField(b []byte, num uint64, v []byte) []byte {
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendVarintField(b []byte, num uint64, v uint64) []byte {
	return appendVarint(appendTag(b, num, wireVarint), v)
}

// maxRecord bounds the size of one geodata record read into memory.
const maxRecord = math.MaxInt32
