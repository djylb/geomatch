package geomatch

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// probe tests one compiled rule on its own, for MatchRule.
type probe struct {
	rule Rule
	geo  *geoIPSet  // the compiled geoip entry of a geo rule
	site *domainSet // the compiled geosite entry of a geo rule
	re   *regexp.Regexp
}

// MatchRule returns the first rule, in the order given to Compile, that addr
// matches, for example to log why a Policy allowed or denied it. It reads
// addr as Match does and costs as much when nothing matches; otherwise it
// tests the rules one by one.
func (m *Matcher) MatchRule(addr string) (Rule, bool) {
	if m == nil {
		return Rule{}, false
	}
	host, ip, isIP := readTarget(addr)
	if isIP && !m.MatchIP(ip) || !isIP && !m.matchDomain(host) {
		return Rule{}, false
	}
	m.once.Do(m.compileProbes)
	for i := range m.probes {
		if m.probes[i].match(host, ip, isIP) {
			return m.probes[i].rule.clone(), true
		}
	}
	return Rule{}, false
}

// compileProbes compiles the regular expressions of the probes, which only
// MatchRule needs.
func (m *Matcher) compileProbes() {
	for i := range m.probes {
		if p := &m.probes[i]; p.rule.Kind == RuleRegexp {
			p.re, _ = regexp.Compile("(?i)" + p.rule.Value)
		}
	}
}

func (p *probe) match(host string, ip netip.Addr, isIP bool) bool {
	r := &p.rule
	if isIP {
		switch {
		case r.Kind == RuleIP:
			return r.Prefix.Contains(ip)
		case p.geo != nil:
			return p.geo.set.contains(ip) != (r.Negate != p.geo.inverse)
		}
		return false
	}
	switch r.Kind {
	case RuleFull:
		return host == r.Value
	case RuleDomain:
		return host == r.Value || isSubdomain(host, r.Value)
	case RuleSubdomain:
		return isSubdomain(host, r.Value)
	case RuleKeyword:
		return strings.Contains(host, r.Value)
	case RuleRegexp:
		return p.re != nil && p.re.MatchString(host)
	case RuleDotless:
		return !strings.Contains(host, ".") && strings.Contains(host, r.Value)
	case RuleGeoSite, RuleExt:
		return p.site != nil && p.site.match(host)
	case RuleIP, RuleGeoIP:
		return false // address rules
	default:
		return false
	}
}

// clone returns r with its own Attrs, so that callers cannot change the
// rules of a Matcher.
func (r Rule) clone() Rule {
	r.Attrs = slices.Clone(r.Attrs)
	return r
}

// isSubdomain reports whether host is a subdomain of domain.
func isSubdomain(host, domain string) bool {
	n := len(host) - len(domain)
	return n > 0 && host[n-1] == '.' && host[n:] == domain
}
