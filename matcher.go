package geomatch

import (
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Matcher matches IP addresses and domain names against compiled rules. It
// is safe for concurrent use. A nil *Matcher matches nothing.
//
// Each query comes in five forms, by what the caller holds: a string that
// HostOf reads, such as host:port or a URL; a netip.Addr; a domain name that
// is never read as an IP address; a net.Addr, such as a connection's
// RemoteAddr; and a domain name with the IP address it resolved to. The
// Match methods report whether a rule matches, and the Find methods which
// rule, at more cost.
type Matcher struct {
	ipSets   []*ipSet     // address rules, then geoip entries shared through GeoData
	inverse  []*ipSet     // geoip:!code and reverse_match entries
	domSets  []*domainSet // domain rules, then geosite entries shared through GeoData
	ipRules  int
	domRules int

	probes []probe   // one per compiled rule, in order, for Find
	once   sync.Once // compiles the regular expressions of probes

	geo     *GeoData
	cfgGen  uint64   // of the files of geo it was compiled from, for Stale
	sources []source // the geodata files read, for Stale

	noRules bool // compiled from no rules at all, for a Policy list not set
}

// Match reports whether addr matches: its host, as HostOf extracts it, is
// matched as an IP address or else as a domain name.
func (m *Matcher) Match(addr string) bool { return m.match(addrTarget(addr)) }

// MatchIP reports whether ip matches an IP rule. IPv4-mapped IPv6 addresses
// match as IPv4.
func (m *Matcher) MatchIP(ip netip.Addr) bool { return m.match(ipTarget(ip)) }

// MatchDomain reports whether host, a domain name or host:port, matches a
// domain rule. IP addresses match no domain rule. Rules and hosts are ASCII:
// write internationalized names in their xn-- (punycode) form.
func (m *Matcher) MatchDomain(host string) bool { return m.match(domainTarget(host)) }

// MatchNetAddr reports whether a, such as a connection's RemoteAddr, matches:
// *net.TCPAddr, *net.UDPAddr and *net.IPAddr are matched by IP address
// without formatting them, Unix socket addresses match no rule, and other
// addresses are matched as Match matches their String.
func (m *Matcher) MatchNetAddr(a net.Addr) bool { return m.match(netAddrTarget(a)) }

// MatchHostIP reports whether a domain name or the IP address it resolved
// to matches: host as MatchDomain reads it, or ip as MatchIP does. Either
// may be empty, as "" or the zero netip.Addr. Unlike checking the two in
// turn, an allowlist then allows a host by either its name or its address.
func (m *Matcher) MatchHostIP(host string, ip netip.Addr) bool {
	return m.match(hostIPTarget(host, ip))
}

// Find returns the first rule, in the order given to Compile, that addr
// matches as Match reads it, for example to log why a Policy allowed or
// denied it, or to choose a route by rule. It costs as much as Match when
// nothing matches; otherwise it tests the rules one by one.
func (m *Matcher) Find(addr string) (Rule, bool) { return m.find(addrTarget(addr)) }

// FindIP is Find for an IP address, as MatchIP reads it.
func (m *Matcher) FindIP(ip netip.Addr) (Rule, bool) { return m.find(ipTarget(ip)) }

// FindDomain is Find for a domain name, as MatchDomain reads it.
func (m *Matcher) FindDomain(host string) (Rule, bool) { return m.find(domainTarget(host)) }

// FindNetAddr is Find for a net.Addr, as MatchNetAddr reads it.
func (m *Matcher) FindNetAddr(a net.Addr) (Rule, bool) { return m.find(netAddrTarget(a)) }

// FindHostIP is Find for a domain name and its IP address, as MatchHostIP
// reads them.
func (m *Matcher) FindHostIP(host string, ip netip.Addr) (Rule, bool) {
	return m.find(hostIPTarget(host, ip))
}

// Stale reports whether a geodata file that m was compiled from has changed
// since, or appeared after it did not exist, or GeoData.SetFiles replaced
// the files, so that compiling the rules again would give a different
// Matcher. It checks the files' metadata only.
func (m *Matcher) Stale() bool {
	if m == nil || m.geo == nil {
		return false
	}
	if m.geo.view().cfgGen != m.cfgGen {
		return true
	}
	for _, s := range m.sources {
		if s.changed() {
			return true
		}
	}
	return false
}

// missingSource reports whether a geodata file of m did not exist, or could
// not be read for the built-in private ranges.
func (m *Matcher) missingSource() bool {
	if m == nil {
		return false
	}
	return slices.ContainsFunc(m.sources, func(s source) bool { return s.info == nil || s.fallback })
}

// Sources returns the geodata files that m was compiled from, in the order
// its rules first read them, for example to log which version of the data
// is in use.
func (m *Matcher) Sources() []Source {
	if m == nil {
		return nil
	}
	out := make([]Source, len(m.sources))
	for i, s := range m.sources {
		out[i] = s.export()
	}
	return out
}

// Matcher returns m, so that a *Matcher is the MatcherSource of a Policy.
func (m *Matcher) Matcher() *Matcher { return m }

// Rules returns the rules compiled into m, in order.
func (m *Matcher) Rules() []Rule {
	if m == nil {
		return nil
	}
	rules := make([]Rule, len(m.probes))
	for i := range m.probes {
		rules[i] = m.probes[i].rule.clone()
	}
	return rules
}

// Len returns the number of rules compiled into m.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.probes)
}

// HasIPRules reports whether m holds rules that match IP addresses, for
// callers that only see one kind of address.
func (m *Matcher) HasIPRules() bool { return m != nil && m.ipRules > 0 }

// HasDomainRules reports whether m holds rules that match domain names.
func (m *Matcher) HasDomainRules() bool { return m != nil && m.domRules > 0 }

func (m *Matcher) match(t target) bool {
	return m.matchIP(t.ip) || m.matchDomain(t.host)
}

// matchIP matches ip, which must be unmapped and without a zone.
func (m *Matcher) matchIP(ip netip.Addr) bool {
	if m == nil || !ip.IsValid() {
		return false
	}
	for _, s := range m.ipSets {
		if s.contains(ip) {
			return true
		}
	}
	for _, s := range m.inverse {
		if !s.contains(ip) {
			return true
		}
	}
	return false
}

// matchDomain matches host, which must be normalized.
func (m *Matcher) matchDomain(host string) bool {
	if m == nil || host == "" {
		return false
	}
	for _, s := range m.domSets {
		if s.match(host) {
			return true
		}
	}
	return false
}

func (m *Matcher) find(t target) (Rule, bool) {
	if !m.match(t) {
		return Rule{}, false
	}
	m.once.Do(m.compileProbes)
	for i := range m.probes {
		if m.probes[i].match(t) {
			return m.probes[i].rule.clone(), true
		}
	}
	return Rule{}, false
}

// probe tests one compiled rule on its own, for Find.
type probe struct {
	rule Rule
	geo  *geoIPSet  // the compiled geoip entry of a geo rule
	site *domainSet // the compiled geosite entry of a geo rule
	re   *regexp.Regexp
}

// compileProbes compiles the regular expressions of the probes, which only
// Find needs.
func (m *Matcher) compileProbes() {
	for i := range m.probes {
		if p := &m.probes[i]; p.rule.Kind == RuleRegexp {
			p.re, _ = regexp.Compile("(?i)" + p.rule.Value)
		}
	}
}

func (p *probe) match(t target) bool {
	return t.ip.IsValid() && p.matchIP(t.ip) || t.host != "" && p.matchHost(t.host)
}

func (p *probe) matchIP(ip netip.Addr) bool {
	switch r := &p.rule; {
	case r.Kind == RuleIP:
		return r.Prefix.Contains(ip)
	case p.geo != nil:
		return p.geo.set.contains(ip) != (r.Negate != p.geo.inverse)
	}
	return false
}

func (p *probe) matchHost(host string) bool {
	r := &p.rule
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
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) clone() Rule {
	r.Attrs = slices.Clone(r.Attrs)
	return r
}

// isSubdomain reports whether host is a subdomain of domain.
func isSubdomain(host, domain string) bool {
	n := len(host) - len(domain)
	return n > 0 && host[n-1] == '.' && host[n:] == domain
}
