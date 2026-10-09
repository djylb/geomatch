package geomatch

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
)

// ipSet is a set of IP addresses stored as sorted, disjoint ranges, one list
// per family, so that a lookup is a binary search. IPv4-mapped IPv6 addresses
// and prefixes are stored and looked up as IPv4.
type ipSet struct {
	v4 []range4
	v6 []range6
}

type range4 struct{ lo, hi uint32 }

type range6 struct{ lo, hi u128 }

// u128 is a 128-bit unsigned integer, an IPv6 address.
type u128 struct{ hi, lo uint64 }

func (a u128) cmp(b u128) int {
	if c := cmp.Compare(a.hi, b.hi); c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

func (a u128) addOne() (u128, bool) {
	lo := a.lo + 1
	hi := a.hi
	if lo == 0 {
		hi++
		if hi == 0 {
			return u128{}, false
		}
	}
	return u128{hi, lo}, true
}

func u128From(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// hostMask128 returns the host bits of a prefix of length bits.
func hostMask128(bits int) u128 {
	switch {
	case bits <= 0:
		return u128{^uint64(0), ^uint64(0)}
	case bits < 64:
		return u128{^uint64(0) >> bits, ^uint64(0)}
	case bits < 128:
		return u128{0, ^uint64(0) >> (bits - 64)}
	default:
		return u128{}
	}
}

// ipSetBuilder collects prefixes and builds an ipSet.
type ipSetBuilder struct {
	v4 []range4
	v6 []range6
}

// addPrefix adds p, which must be valid.
func (b *ipSetBuilder) addPrefix(p netip.Prefix) {
	addr, bits := p.Addr().WithZone(""), p.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr, bits = addr.Unmap(), bits-96
	}
	if addr.Is4() {
		v4 := addr.As4()
		v := binary.BigEndian.Uint32(v4[:])
		mask := uint32(0)
		if bits < 32 {
			mask = ^uint32(0) >> bits
		}
		b.v4 = append(b.v4, range4{v &^ mask, v | mask})
		return
	}
	v, mask := u128From(addr), hostMask128(bits)
	b.v6 = append(b.v6, range6{u128{v.hi &^ mask.hi, v.lo &^ mask.lo}, u128{v.hi | mask.hi, v.lo | mask.lo}})
}

// addAddr adds a single address.
func (b *ipSetBuilder) addAddr(a netip.Addr) {
	a = a.Unmap().WithZone("")
	b.addPrefix(netip.PrefixFrom(a, a.BitLen()))
}

// build sorts and merges the ranges. The builder can be reused afterwards.
func (b *ipSetBuilder) build() *ipSet {
	s := &ipSet{}
	if len(b.v4) > 0 {
		slices.SortFunc(b.v4, func(x, y range4) int { return cmp.Compare(x.lo, y.lo) })
		out := []range4{b.v4[0]}
		for _, r := range b.v4[1:] {
			last := &out[len(out)-1]
			// Merge overlapping and adjacent ranges.
			if last.hi == ^uint32(0) || r.lo <= last.hi+1 {
				last.hi = max(last.hi, r.hi)
				continue
			}
			out = append(out, r)
		}
		s.v4 = slices.Clip(out)
	}
	if len(b.v6) > 0 {
		slices.SortFunc(b.v6, func(x, y range6) int { return x.lo.cmp(y.lo) })
		out := []range6{b.v6[0]}
		for _, r := range b.v6[1:] {
			last := &out[len(out)-1]
			next, ok := last.hi.addOne()
			if !ok || r.lo.cmp(next) <= 0 {
				if r.hi.cmp(last.hi) > 0 {
					last.hi = r.hi
				}
				continue
			}
			out = append(out, r)
		}
		s.v6 = slices.Clip(out)
	}
	b.v4, b.v6 = nil, nil
	return s
}

// contains reports whether a, which must be unmapped, is in the set.
func (s *ipSet) contains(a netip.Addr) bool {
	if a.Is4() {
		v4 := a.As4()
		v := binary.BigEndian.Uint32(v4[:])
		i, _ := slices.BinarySearchFunc(s.v4, v, func(r range4, v uint32) int {
			if r.hi < v {
				return -1
			}
			return 1
		})
		return i < len(s.v4) && s.v4[i].lo <= v
	}
	v := u128From(a)
	i, _ := slices.BinarySearchFunc(s.v6, v, func(r range6, v u128) int {
		if r.hi.cmp(v) < 0 {
			return -1
		}
		return 1
	})
	return i < len(s.v6) && s.v6[i].lo.cmp(v) <= 0
}

// ranges returns the number of disjoint ranges in the set.
func (s *ipSet) ranges() int {
	return len(s.v4) + len(s.v6)
}

// mergeIPSets returns a set holding the addresses of sets.
func mergeIPSets(sets []*ipSet) *ipSet {
	var b ipSetBuilder
	for _, s := range sets {
		b.v4 = append(b.v4, s.v4...)
		b.v6 = append(b.v6, s.v6...)
	}
	return b.build()
}
