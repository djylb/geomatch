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
	// address are found by masking it with each length. An address range
	// is the CIDR prefixes that cover it.
	prefixes map[netip.Prefix]int
	lengths  [2][3]uint64
	// exact maps a name to the first full: or domain: rule of it, and sub
	// to the first domain: or *. rule that its subdomains match.
	exact, sub map[string]int
	// keywords finds keyword rules, by literal id, the rule being
	// keywordRules[id].
	keywords     *literalIndex
	keywordRules []int
	// others are the other rules, in order, tried one by one, those with
	// ports among them.
	others []int
	// ported indexes the rules with ports alike, but every rule of a key,
	// in order, since the first may not hold the port; nil without them.
	ported *portedExplain
}

// portedExplain indexes the rules with ports as explainIndex the others.
type portedExplain struct {
	prefixes     map[netip.Prefix][]int
	lengths      [2][3]uint64
	exact, sub   map[string][]int
	keywords     *literalIndex
	keywordRules []int
}

func newExplainIndex(probes []probe) *explainIndex {
	x := &explainIndex{prefixes: make(map[netip.Prefix]int), exact: make(map[string]int), sub: make(map[string]int)}
	first := func(m map[string]int, k string, i int) {
		if _, ok := m[k]; !ok {
			m[k] = i
		}
	}
	var px *portedExplain
	var keywords, pkeywords []string
	var ps []netip.Prefix
	for i := range probes {
		r := &probes[i].rule
		if len(r.Ports) > 0 {
			if px == nil {
				px = &portedExplain{prefixes: make(map[netip.Prefix][]int), exact: make(map[string][]int), sub: make(map[string][]int)}
			}
			switch r.Kind {
			case RuleIP:
				for _, p := range rulePrefixes(r, ps[:0]) {
					if px.prefixes[p] == nil {
						addLength(&px.lengths, p)
					}
					px.prefixes[p] = append(px.prefixes[p], i)
				}
			case RuleFull, RuleDomain, RuleSubdomain:
				flags := nameFlags(r.Kind)
				if flags&nameExact != 0 {
					px.exact[r.Value] = append(px.exact[r.Value], i)
				}
				if flags&nameSub != 0 {
					px.sub[r.Value] = append(px.sub[r.Value], i)
				}
			case RuleKeyword:
				pkeywords = append(pkeywords, r.Value)
				px.keywordRules = append(px.keywordRules, i)
			default:
				x.others = append(x.others, i)
			}
			continue
		}
		switch r.Kind {
		case RuleIP:
			for _, p := range rulePrefixes(r, ps[:0]) {
				if _, ok := x.prefixes[p]; !ok {
					x.prefixes[p] = i
					addLength(&x.lengths, p)
				}
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
	if px != nil && len(pkeywords) > 0 {
		px.keywords = newLiteralIndex(pkeywords)
	}
	x.ported = px
	return x
}

// rulePrefixes appends the masked CIDR prefixes of a RuleIP to out.
func rulePrefixes(r *Rule, out []netip.Prefix) []netip.Prefix {
	if r.Last.IsValid() {
		return rangePrefixes(r.Prefix.Addr(), r.Last, out)
	}
	return append(out, r.Prefix.Masked())
}

// addLength records the length of p among lengths.
func addLength(lengths *[2][3]uint64, p netip.Prefix) {
	fam := 0
	if p.Addr().Is6() {
		fam = 1
	}
	lengths[fam][p.Bits()/64] |= 1 << (p.Bits() % 64)
}

// first returns the index of the first rule of probes that matches t as
// Matcher.Match does, or -1.
func (x *explainIndex) first(probes []probe, t target) int {
	return x.firstFor(probes, t, t.portOf(), false)
}

// firstFor returns the index of the first rule of probes that matches t,
// whose port is port, allow reading ports as Matcher.match does, or -1.
func (x *explainIndex) firstFor(probes []probe, t target, port int32, allow bool) int {
	best := x.indexed(t)
	if x.ported != nil {
		best = x.ported.first(probes, t, port, allow, best)
	}
	for _, i := range x.others {
		if best >= 0 && i > best {
			break
		}
		if probes[i].matchFor(t, port, allow) {
			return i
		}
	}
	return best
}

// indexed returns the first of the rules without ports that the maps and
// keywords find for t, or -1.
func (x *explainIndex) indexed(t target) int {
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
	return best
}

// first returns the first rule with ports that holds port and that the maps
// and keywords find for t, if it comes before best, or else best.
func (px *portedExplain) first(probes []probe, t target, port int32, allow bool, best int) int {
	// The first rule of a list that holds the port.
	firstOf := func(list []int) {
		for _, i := range list {
			if best >= 0 && i > best {
				return
			}
			if portsHold(probes[i].ports, port, allow) {
				best = i
				return
			}
		}
	}
	if ip := t.ip; ip.IsValid() {
		fam := 0
		if ip.Is6() {
			fam = 1
		}
		for w := range px.lengths[fam] {
			for set := px.lengths[fam][w]; set != 0; set &= set - 1 {
				n := w*64 + bits.TrailingZeros64(set)
				if p, err := ip.Prefix(n); err == nil {
					firstOf(px.prefixes[p])
				}
			}
		}
	}
	if host := t.host; host != "" {
		firstOf(px.exact[host])
		for j := range len(host) {
			if host[j] == '.' {
				firstOf(px.sub[host[j+1:]])
			}
		}
		if px.keywords != nil {
			px.keywords.scan(host, func(id int32) bool {
				if i := px.keywordRules[id]; (best < 0 || i < best) && portsHold(probes[i].ports, port, allow) {
					best = i
				}
				return false
			})
		}
	}
	return best
}
