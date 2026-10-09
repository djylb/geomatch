package geomatch

import (
	"regexp"
	"slices"
	"strings"
)

// domainSet matches normalized host names: lowercase, without a trailing dot.
// After finish, keywords and the literals that regular expressions require
// are found in one pass over the host, and only the regular expressions whose
// literal occurs run.
type domainSet struct {
	names      map[string]uint8 // full: and suffix rules until finish
	table      *domainTable     // names after finish
	index      *literalIndex    // keywords, then the literals of litOwner
	keywords   []string
	regexps    []*regexp.Regexp
	lits       []string // the literal each regexp requires, or ""
	dotless    []string
	litOwner   []int // the regexp of each literal after the keywords
	free       []int // regexps without a literal
	dotlessAny bool
	active     bool // some rule was added
}

// addName adds a full: or suffix rule with nameExact and nameSub flags.
func (d *domainSet) addName(name string, flags uint8) {
	if d.names == nil {
		d.names = make(map[string]uint8)
	}
	d.names[name] |= flags
}

func (d *domainSet) addKeyword(keyword string) {
	d.keywords = append(d.keywords, keyword)
}

func (d *domainSet) addRegexp(pattern string) error {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return err
	}
	d.regexps = append(d.regexps, re)
	d.lits = append(d.lits, requiredLiteral(pattern))
	return nil
}

// finish builds the name table and the literal index once every rule is
// added.
func (d *domainSet) finish() {
	if d.names != nil {
		d.table = newDomainTable(d.names)
		d.names = nil
	}
	lits := slices.Clone(d.keywords)
	d.litOwner, d.free = nil, nil
	for i, lit := range d.lits {
		if lit == "" {
			d.free = append(d.free, i)
			continue
		}
		lits = append(lits, lit)
		d.litOwner = append(d.litOwner, i)
	}
	d.index = nil
	if len(lits) > 0 {
		d.index = newLiteralIndex(lits)
	}
	d.active = d.table != nil || d.index != nil || len(d.free) > 0 || d.dotlessAny || len(d.dotless) > 0
}

// match reports whether host, which must be normalized, matches.
func (d *domainSet) match(host string) bool {
	if !d.active || host == "" {
		return false
	}
	if d.table != nil && d.table.match(host) {
		return true
	}
	if d.index != nil {
		// Under case folding a non-ASCII host can match a regexp without
		// containing its literal byte for byte, so those run regardless.
		ascii := isASCII(host)
		hit := d.index.scan(host, func(id int32) bool {
			if int(id) < len(d.keywords) {
				return true
			}
			return ascii && d.regexps[d.litOwner[int(id)-len(d.keywords)]].MatchString(host)
		})
		if hit {
			return true
		}
		if !ascii {
			for _, i := range d.litOwner {
				if d.regexps[i].MatchString(host) {
					return true
				}
			}
		}
	}
	for _, i := range d.free {
		if d.regexps[i].MatchString(host) {
			return true
		}
	}
	if (d.dotlessAny || len(d.dotless) > 0) && !strings.Contains(host, ".") {
		if d.dotlessAny {
			return true
		}
		for _, k := range d.dotless {
			if strings.Contains(host, k) {
				return true
			}
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// addDomains adds geosite entries.
func (d *domainSet) addDomains(domains []Domain) {
	for _, dom := range domains {
		switch dom.Type {
		case DomainFull:
			d.addName(dom.Value, nameExact)
		case DomainRoot:
			d.addName(dom.Value, nameExact|nameSub)
		case DomainKeyword:
			d.addKeyword(dom.Value)
		case DomainRegexp:
			// An entry that does not compile is left out.
			_ = d.addRegexp(dom.Value)
		}
	}
}

// mergeDomainSets returns a set holding the rules of finished sets, which
// share their compiled regular expressions with it.
func mergeDomainSets(sets []*domainSet) *domainSet {
	m := &domainSet{}
	for _, s := range sets {
		if t := s.table; t != nil {
			start := uint32(0)
			for i, end := range t.ends {
				m.addName(string(t.data[start:end]), t.flags[i])
				start = end
			}
		}
		m.keywords = append(m.keywords, s.keywords...)
		m.regexps = append(m.regexps, s.regexps...)
		m.lits = append(m.lits, s.lits...)
		m.dotless = append(m.dotless, s.dotless...)
		m.dotlessAny = m.dotlessAny || s.dotlessAny
	}
	m.finish()
	return m
}
