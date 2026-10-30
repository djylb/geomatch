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
// Each query comes in six forms, by what the caller holds: a string that
// HostOf reads, such as host:port or a URL; a netip.Addr; a domain name that
// is never read as an IP address; a net.Addr, such as a connection's
// RemoteAddr; a domain name with the IP address it resolved to; and a
// netip.AddrPort. The Match methods report whether a rule
// matches, and the Find methods which rule, at more cost.
//
// Rules with ports (Rule.Ports) match a query by its port as well: the port
// of a host:port or [IPv6]:port string, of a URL, explicit or the default of
// http, https, ws, wss and ftp, of a *net.TCPAddr or *net.UDPAddr, or of a
// netip.AddrPort, which MatchAddrPort and FindAddrPort take. A query without
// a port, such as a bare host, a netip.Addr or a *net.IPAddr, matches no
// rule with ports, and one whose port cannot be read, such as host:https,
// matches them by address alone, so that a denylist fails closed; a
// Policy's Allow list reads both the other way round. So do not use a bare
// Matcher with port rules as an allowlist: a port that cannot be read would
// pass it. Use Policy{Allow: m}. Rules without ports
// match every query as before.
type Matcher struct {
	ipSets    []*ipSet     // address rules, then geoip entries shared through GeoData
	inverse   []*ipSet     // geoip:!code and reverse_match entries
	domSets   []*domainSet // domain rules, then geosite entries shared through GeoData
	ports     *portIndex   // the rules with ports, or nil
	anyAddr   bool         // of a Matcher of ports: a port rule matches every address
	ipRules   int
	domRules  int
	portRules int

	probes  []probe       // one per compiled rule, in order, for Find
	once    sync.Once     // builds explain
	explain *explainIndex // finds the first rule that matches, for Find

	snapshot // the geodata it was compiled from, for Stale
}

// Match reports whether addr matches: its host, as HostOf extracts it, is
// matched as an IP address or else as a domain name.
func (m *Matcher) Match(addr string) bool { return m.match(addrTarget(addr), false) }

// MatchIP reports whether ip matches an IP rule. IPv4-mapped IPv6 addresses
// match as IPv4.
func (m *Matcher) MatchIP(ip netip.Addr) bool { return m.match(ipTarget(ip), false) }

// MatchAddrPort reports whether the address and port of ap match, as
// MatchIP matches the address and rules with ports also the port.
func (m *Matcher) MatchAddrPort(ap netip.AddrPort) bool { return m.match(addrPortTarget(ap), false) }

// MatchDomain reports whether host, a domain name or host:port, matches a
// domain rule. IP addresses, also in the legacy forms of IPv4, match no
// domain rule. Internationalized names are matched in their xn-- form.
func (m *Matcher) MatchDomain(host string) bool { return m.match(domainTarget(host), false) }

// MatchNetAddr reports whether a, such as a connection's RemoteAddr, matches:
// *net.TCPAddr, *net.UDPAddr and *net.IPAddr are matched by IP address
// without formatting them, Unix socket addresses match no rule, and other
// addresses are matched as Match matches their String.
func (m *Matcher) MatchNetAddr(a net.Addr) bool { return m.match(netAddrTarget(a), false) }

// MatchHostIP reports whether a domain name or the IP address it resolved
// to matches: host as MatchDomain reads it, or ip as MatchIP does. Either
// may be empty, as "" or the zero netip.Addr. Unlike checking the two in
// turn, an allowlist then allows a host by either its name or its address.
func (m *Matcher) MatchHostIP(host string, ip netip.Addr) bool {
	return m.match(hostIPTarget(host, ip), false)
}

// Find returns the first rule, in the order given to Compile, that addr
// matches as Match reads it, for example to log why a Policy allowed or
// denied it, or to choose a route by rule. It costs as much as Match when
// nothing matches; otherwise it tests the rules one by one.
func (m *Matcher) Find(addr string) (Rule, bool) { return m.find(addrTarget(addr), false) }

// FindIP is Find for an IP address, as MatchIP reads it.
func (m *Matcher) FindIP(ip netip.Addr) (Rule, bool) { return m.find(ipTarget(ip), false) }

// FindAddrPort is Find for an address and port, as MatchAddrPort reads them.
func (m *Matcher) FindAddrPort(ap netip.AddrPort) (Rule, bool) {
	return m.find(addrPortTarget(ap), false)
}

// FindDomain is Find for a domain name, as MatchDomain reads it.
func (m *Matcher) FindDomain(host string) (Rule, bool) { return m.find(domainTarget(host), false) }

// FindNetAddr is Find for a net.Addr, as MatchNetAddr reads it.
func (m *Matcher) FindNetAddr(a net.Addr) (Rule, bool) { return m.find(netAddrTarget(a), false) }

// FindHostIP is Find for a domain name and its IP address, as MatchHostIP
// reads them.
func (m *Matcher) FindHostIP(host string, ip netip.Addr) (Rule, bool) {
	return m.find(hostIPTarget(host, ip), false)
}

// Stale reports whether a geodata file that m was compiled from has changed
// since, or appeared after it did not exist, or GeoData.SetFiles replaced
// the files, so that compiling the rules again would give a different
// Matcher. It checks the files' metadata only.
func (m *Matcher) Stale() bool {
	return m != nil && m.stale(false)
}

// snapshot is the geodata that a compile read: the files of a GeoData, and
// the version of each file read.
type snapshot struct {
	geo     *GeoData
	cfgGen  uint64   // of the files of geo, for stale
	sources []source // the geodata files read, for stale
}

// stale reports whether compiling the rules again would read other geodata,
// as Matcher.Stale does. With checked, which GeoData.RefreshLives passes
// right after GeoData.Check, a file that the GeoData holds the index of is
// compared with the version that the GeoData recorded rather than looked at
// again: Check dropped the indexes of the files that changed, which are
// looked at, as are those that the GeoData holds no index of.
func (s *snapshot) stale(checked bool) bool {
	g := s.geo
	if g == nil {
		return false
	}
	g.mu.Lock()
	if g.cfgGen != s.cfgGen {
		g.mu.Unlock()
		return true
	}
	unknown := s.sources // the files to look at
	if checked {
		unknown = nil
		for _, src := range s.sources {
			f, ok := g.files[src.name]
			switch {
			case !ok || src.info == nil:
				unknown = append(unknown, src)
			case !sameVersion(f.info, src.info):
				g.mu.Unlock()
				return true
			}
		}
	}
	g.mu.Unlock()
	return slices.ContainsFunc(unknown, source.changed)
}

// missing reports whether a geodata file of s did not exist, or could not be
// read for the built-in private ranges.
func (s *snapshot) missing() bool {
	return slices.ContainsFunc(s.sources, func(src source) bool { return src.info == nil || src.fallback })
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

// HasPortRules reports whether m holds rules with ports, so that a caller
// passes the port of an address, such as with MatchAddrPort, only when it
// could change the answer.
func (m *Matcher) HasPortRules() bool { return m != nil && m.portRules > 0 }

// match reports whether a rule matches t. allow reads rules with ports as
// an allowlist does: a target without a port matches them by address, and
// one whose port cannot be read does not.
func (m *Matcher) match(t target, allow bool) bool {
	if m == nil {
		return false
	}
	if m.matchIP(t.ip) || m.matchDomain(t.host) {
		return true
	}
	return m.ports != nil && m.ports.match(t, t.portOf(), allow)
}

// matchAny matches t against the rules of a Matcher of the portIndex,
// whose rules are without their ports.
func (m *Matcher) matchAny(t target) bool {
	return m.matchIP(t.ip) || m.matchDomain(t.host) || m.anyAddr && (t.ip.IsValid() || t.host != "")
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

func (m *Matcher) find(t target, allow bool) (Rule, bool) {
	if !m.match(t, allow) {
		return Rule{}, false
	}
	m.once.Do(m.buildExplain)
	port := int32(portNone)
	if m.ports != nil {
		port = t.portOf()
	}
	if i := m.explain.firstFor(m.probes, t, port, allow); i >= 0 {
		return m.probes[i].found(), true
	}
	return Rule{}, false
}

// probe tests one compiled rule on its own, for Find.
type probe struct {
	rule Rule
	geo  *geoIPSet      // the compiled geoip entry of a geo rule
	site *domainSet     // the compiled geosite entry of a geo rule
	re   *regexp.Regexp // of a regexp: rule, shared with its domainSet
	// ports are the rule's ports, which Find shares with callers in
	// rule.Ports, so that a caller that changes those does not change
	// what the rule matches.
	ports []PortRange
}

// buildExplain builds the index of the rules, which only Find needs.
func (m *Matcher) buildExplain() {
	m.explain = newExplainIndex(m.probes)
}

// found returns the rule for Find, with its own Attrs, and Ports shared,
// so that Find does not allocate for them: the probe matches by ports, its
// own copy.
func (p *probe) found() Rule {
	r := p.rule
	r.Attrs = slices.Clone(r.Attrs)
	return r
}

// match reports whether the rule matches t as Matcher.Match does.
func (p *probe) match(t target) bool {
	return p.matchFor(t, t.portOf(), false)
}

// matchFor reports whether the rule matches t, whose port is port, allow
// reading ports as Matcher.match does.
func (p *probe) matchFor(t target, port int32, allow bool) bool {
	return (t.ip.IsValid() && p.matchIP(t.ip) || t.host != "" && p.matchHost(t.host)) &&
		portsHold(p.ports, port, allow)
}

func (p *probe) matchIP(ip netip.Addr) bool {
	switch r := &p.rule; {
	case r.Kind == RulePort:
		return true
	case r.Kind == RuleIP && r.Last.IsValid():
		return !ip.Less(r.Prefix.Addr()) && !r.Last.Less(ip) && ip.Is4() == r.Last.Is4()
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
	case RuleFull, RuleDomain, RuleSubdomain:
		return matchName(host, r.Value, nameFlags(r.Kind))
	case RuleKeyword:
		return strings.Contains(host, r.Value)
	case RuleRegexp:
		return p.re != nil && p.re.MatchString(host)
	case RuleDotless:
		return !strings.Contains(host, ".") && strings.Contains(host, r.Value)
	case RuleGeoSite, RuleExt:
		return p.site != nil && p.site.match(host)
	case RulePort:
		return true
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
	r.Ports = slices.Clone(r.Ports)
	return r
}
