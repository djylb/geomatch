package geomatch

import "math/bits"

// Flags of the names in a domainTable.
const (
	nameExact = 1 << iota // the name itself matches (full:, domain:, *name)
	nameSub               // its subdomains match (domain:, *name, *.name)
)

// rollPrime is the multiplier of the rolling hash, which runs from the end of
// a name so that one pass over a host yields the hash of every suffix.
const rollPrime = 0x100000001b3

// rollHash returns the rolling hash of s, as domainTable.match computes it.
func rollHash(s string) uint64 {
	var h uint64
	for i := len(s) - 1; i >= 0; i-- {
		h = h*rollPrime + uint64(s[i])
	}
	return h
}

// domainTable is an open-addressing hash table of domain names keyed by
// their rolling hash. Names are stored back to back in one buffer, so the
// table takes a few bytes per name beyond the names themselves.
type domainTable struct {
	slots []uint64 // the hash's upper half and the name's index+1; 0 is empty
	shift uint     // 64 - log2(len(slots))
	data  []byte   // the names, back to back
	ends  []uint32 // the end of each name in data
	flags []uint8  // nameExact and nameSub of each name
	sub   bool     // some name has nameSub
}

// newDomainTable builds a table of names, each with its flags.
func newDomainTable(names map[string]uint8) *domainTable {
	if len(names) == 0 {
		return nil
	}
	size := 1 << max(bits.Len(uint(len(names))*2), 3) // load factor at most 1/2
	t := &domainTable{
		slots: make([]uint64, size),
		shift: uint(64 - bits.TrailingZeros(uint(size))),
		ends:  make([]uint32, 0, len(names)),
		flags: make([]uint8, 0, len(names)),
	}
	for name, f := range names {
		t.data = append(t.data, name...)
		t.ends = append(t.ends, uint32(len(t.data)))
		t.flags = append(t.flags, f)
		t.sub = t.sub || f&nameSub != 0
		h := rollHash(name)
		i := t.index(h)
		for t.slots[i] != 0 {
			i = (i + 1) & uint64(len(t.slots)-1)
		}
		t.slots[i] = h&^0xffffffff | uint64(len(t.ends))
	}
	return t
}

func (t *domainTable) index(h uint64) uint64 {
	return (h * 0x9e3779b97f4a7c15) >> t.shift
}

// lookup returns the flags of name, whose rolling hash is h, or 0.
func (t *domainTable) lookup(h uint64, name string) uint8 {
	mask := uint64(len(t.slots) - 1)
	for i := t.index(h); ; i = (i + 1) & mask {
		slot := t.slots[i]
		if slot == 0 {
			return 0
		}
		if slot&^0xffffffff != h&^0xffffffff {
			continue
		}
		n := uint32(slot) - 1
		start := uint32(0)
		if n > 0 {
			start = t.ends[n-1]
		}
		if string(t.data[start:t.ends[n]]) == name {
			return t.flags[n]
		}
	}
}

// match reports whether host is a name with nameExact or a subdomain of a
// name with nameSub. It hashes the host once, from the end, looking up each
// suffix that follows a dot as it goes.
func (t *domainTable) match(host string) bool {
	var h uint64
	for i := len(host) - 1; i >= 0; i-- {
		c := host[i]
		if c == '.' && t.sub && t.lookup(h, host[i+1:])&nameSub != 0 {
			return true
		}
		h = h*rollPrime + uint64(c)
	}
	return t.lookup(h, host)&nameExact != 0
}
