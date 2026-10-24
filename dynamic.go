package geomatch

import (
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// IPSet is a set of IP prefixes that changes while it is used, such as the
// addresses that clients register at run time, and a MatcherSource of them
// for a Policy, Levels or Router, which see each change at their next query.
// The rules of its Matcher are the prefixes, as Find and Decide report them.
//
// A change costs little; the next Matcher builds the set again, in time
// that grows as n log n with its size, once for any number of changes before
// it. For sets of many thousands of prefixes that change between most
// queries, apply changes in batches, as with one Add of many prefixes, so
// that queries do not build it each time. The zero IPSet is empty and ready to use, and its methods are safe for
// concurrent use.
type IPSet struct {
	mu       sync.Mutex
	prefixes map[netip.Prefix]struct{}
	cur      atomic.Pointer[Matcher] // nil when a change came after it
}

// Add adds prefixes, and single addresses as prefixes of their full length,
// such as netip.PrefixFrom(addr, addr.BitLen()). Prefixes are masked, and
// IPv4-mapped ones are IPv4; invalid ones are ignored.
func (s *IPSet) Add(prefixes ...netip.Prefix) {
	s.change(prefixes, true)
}

// Remove removes prefixes as Add added them.
func (s *IPSet) Remove(prefixes ...netip.Prefix) {
	s.change(prefixes, false)
}

func (s *IPSet) change(prefixes []netip.Prefix, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prefixes == nil {
		s.prefixes = make(map[netip.Prefix]struct{})
	}
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		p = normalPrefix(p)
		if _, ok := s.prefixes[p]; ok == add {
			continue
		}
		if add {
			s.prefixes[p] = struct{}{}
		} else {
			delete(s.prefixes, p)
		}
		s.cur.Store(nil)
	}
}

// Prefixes returns the prefixes of the set, sorted.
func (s *IPSet) Prefixes() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked()
}

func (s *IPSet) sortedLocked() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.prefixes))
	for p := range s.prefixes {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// Len returns the number of prefixes of the set.
func (s *IPSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.prefixes)
}

// Matcher returns a Matcher of the prefixes as they are now, built again
// when they changed since the last one, and taken without locking while they
// did not; it implements MatcherSource. A nil IPSet has none.
func (s *IPSet) Matcher() *Matcher {
	if s == nil {
		return nil
	}
	if m := s.cur.Load(); m != nil {
		return m
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.cur.Load(); m != nil {
		return m
	}
	b := newBuilder(nil)
	for _, p := range s.sortedLocked() {
		_ = b.add(Rule{Kind: RuleIP, Prefix: p}) // never fails for a valid prefix
	}
	m := b.finish()
	s.cur.Store(m)
	return m
}
