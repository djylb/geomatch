package geomatch

import (
	"regexp"
	"slices"
	"strings"
)

// Suffix flags of domainSet.suffix.
const (
	suffixSelf = 1 << iota // the domain itself
	suffixSub              // its subdomains
)

// domainSet matches normalized host names: lowercase, without a trailing dot.
// After finish, keywords and the literals that regular expressions require
// are found in one pass over the host, and only the regular expressions whose
// literal occurs run.
type domainSet struct {
	full       map[string]struct{}
	suffix     map[string]uint8
	keywords   []string
	regexps    []*regexp.Regexp
	lits       []string // the literal each regexp requires, or ""
	dotless    []string
	dotlessAny bool

	index    *literalIndex // keywords, then the literals of litOwner
	litOwner []int         // the regexp of each literal after the keywords
	free     []int         // regexps without a literal
}

func (d *domainSet) addFull(host string) {
	if d.full == nil {
		d.full = make(map[string]struct{})
	}
	d.full[host] = struct{}{}
}

func (d *domainSet) addSuffix(domain string, flags uint8) {
	if d.suffix == nil {
		d.suffix = make(map[string]uint8)
	}
	d.suffix[domain] |= flags
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

// finish builds the literal index once every rule is added.
func (d *domainSet) finish() {
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
}

// match reports whether host, which must be normalized, matches.
func (d *domainSet) match(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := d.full[host]; ok {
		return true
	}
	if len(d.suffix) > 0 {
		if d.suffix[host]&suffixSelf != 0 {
			return true
		}
		for rest := host; ; {
			i := strings.IndexByte(rest, '.')
			if i < 0 {
				break
			}
			rest = rest[i+1:]
			if d.suffix[rest]&suffixSub != 0 {
				return true
			}
		}
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
			d.addFull(dom.Value)
		case DomainRoot:
			d.addSuffix(dom.Value, suffixSelf|suffixSub)
		case DomainKeyword:
			d.addKeyword(dom.Value)
		case DomainRegexp:
			// An entry that does not compile is left out.
			_ = d.addRegexp(dom.Value)
		}
	}
}
