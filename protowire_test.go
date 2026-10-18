package geomatch

import "encoding/binary"

// appendVarint and the helpers below encode messages for tests.
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
