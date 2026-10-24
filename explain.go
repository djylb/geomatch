package geomatch

import (
	"math/bits"
	"net/netip"
)

// explainIndex finds the first rule of a Matcher that matches a target
// without trying the rules one by one, for Find and Decide: CIDR prefixes,
// names and keywords, which large lists hold most of, are looked up, and
// only the rules of other kinds are tried in order, up to the best rule
// found. It is built on the first use.
type explainIndex struct {
	// prefixes maps a masked prefix to the first rule of it, and lengths
	// holds the prefix lengths in use, a bit each, for IPv4 and IPv6. CIDR
	// prefixes are either nested or apart, so the rules that hold an
	// address are found by masking it with each length.
	prefixes map[netip.Prefix]int
	lengths  [2][3]uint64
	// exact maps a name to the first full: or domain: rule of it, and sub
	// to the first domain: or *. rule that its subdomains match.
	exact, sub map[string]int
	// keywords finds keyword rules, by literal id, the rule being
	// keywordRules[id].
	keywords     *literalIndex
	keywordRules []int
	// others are the other rules, in order, tried one by one.
	others []int
}

func newExplainIndex(probes []probe) *explainIndex {
	x := &explainIndex{prefixes: make(map[netip.Prefix]int), exact: make(map[string]int), sub: make(map[string]int)}
	first := func(m map[string]int, k string, i int) {
		if _, ok := m[k]; !ok {
			m[k] = i
		}
	}
	var keywords []string
	for i := range probes {
		r := &probes[i].rule
		switch r.Kind {
		case RuleIP:
			p := r.Prefix.Masked()
			if _, ok := x.prefixes[p]; !ok {
				x.prefixes[p] = i
				fam := 0
				if p.Addr().Is6() {
					fam = 1
				}
				x.lengths[fam][p.Bits()/64] |= 1 << (p.Bits() % 64)
			}
		case RuleFull, RuleDomain, RuleSubdomain:
			flags := nameFlags(r.Kind)
			if flags&nameExact != 0 {
				first(x.exact, r.Value, i)
			}
			if flags&nameSub != 0 {
				first(x.sub, r.Value, i)
			}
		case RuleKeyword:
			keywords = append(keywords, r.Value)
			x.keywordRules = append(x.keywordRules, i)
		default:
			x.others = append(x.others, i)
		}
	}
	if len(keywords) > 0 {
		x.keywords = newLiteralIndex(keywords)
	}
	return x
}

// first returns the index of the first rule of probes that matches t, or
// -1.
func (x *explainIndex) first(probes []probe, t target) int {
	best := -1
	better := func(i int) {
		if best < 0 || i < best {
			best = i
		}
	}
	if ip := t.ip; ip.IsValid() {
		fam := 0
		if ip.Is6() {
			fam = 1
		}
		for w := range x.lengths[fam] {
			for set := x.lengths[fam][w]; set != 0; set &= set - 1 {
				n := w*64 + bits.TrailingZeros64(set)
				if p, err := ip.Prefix(n); err == nil {
					if i, ok := x.prefixes[p]; ok {
						better(i)
					}
				}
			}
		}
	}
	if host := t.host; host != "" {
		if i, ok := x.exact[host]; ok {
			better(i)
		}
		for j := range len(host) {
			if host[j] == '.' {
				if i, ok := x.sub[host[j+1:]]; ok {
					better(i)
				}
			}
		}
		if x.keywords != nil {
			x.keywords.scan(host, func(id int32) bool {
				better(x.keywordRules[id])
				return false
			})
		}
	}
	for _, i := range x.others {
		if best >= 0 && i > best {
			break
		}
		if probes[i].match(t) {
			return i
		}
	}
	return best
}
