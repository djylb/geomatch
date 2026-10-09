package geomatch

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// RuleError reports a rule that Compile skipped.
type RuleError struct {
	// Index is the position of the rule in the slice given to Compile.
	Index int
	Rule  string
	Err   error
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("geomatch: rule %d %q: %v", e.Index, e.Rule, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// Options configures Compile.
type Options struct {
	// GeoData reads geoip:, geosite: and ext: rules. Nil reads only ext:
	// files, relative to the working directory; geoip:private still works.
	GeoData *GeoData
}

// Matcher matches IP addresses and domain names against compiled rules. It
// is safe for concurrent use. A nil *Matcher matches nothing.
type Matcher struct {
	ipSets   []*ipSet     // address rules, then geoip entries shared through GeoData
	inverse  []*ipSet     // geoip:!code and reverse_match entries
	domSets  []*domainSet // domain rules, then geosite entries shared through GeoData
	ipRules  int
	domRules int

	probes []probe   // one per compiled rule, in order, for MatchRule
	once   sync.Once // compiles the regular expressions of probes
}

// SplitRules splits text into rules, one per line, trimming spaces and
// dropping empty lines. Comments are kept for Compile to skip. To report
// errors by line number, split on newlines yourself: Compile skips empty
// rules, so RuleError.Index is then the line number less one.
func SplitRules(text string) []string {
	var rules []string
	for line := range strings.Lines(text) {
		if line = strings.TrimSpace(line); line != "" {
			rules = append(rules, line)
		}
	}
	return rules
}

// Compile compiles rules into a Matcher; the package documentation lists the
// syntax. Empty rules and comments, starting with # or ;, are skipped.
// Invalid rules, and rules whose geodata cannot be read, are skipped too: the
// returned error joins a *RuleError for each, and the Matcher holds the
// valid rules.
func Compile(rules []string, opts Options) (*Matcher, error) {
	c := newCompiler(opts)
	var errs []error
	for i, s := range rules {
		r, err := ParseRule(s)
		if errors.Is(err, errNoRule) {
			continue
		}
		if err == nil {
			err = c.add(r)
		}
		if err != nil {
			errs = append(errs, &RuleError{Index: i, Rule: strings.TrimSpace(s), Err: err})
		}
	}
	return c.finish(), errors.Join(errs...)
}

// CompileRules is Compile for parsed rules, such as those ParseRule returns
// or a program builds. Each rule is checked and normalized as its String
// form would be.
func CompileRules(rules []Rule, opts Options) (*Matcher, error) {
	c := newCompiler(opts)
	var errs []error
	for i, r := range rules {
		s := r.String()
		n, err := ParseRule(s)
		if err == nil {
			err = c.add(n)
		}
		if err != nil {
			errs = append(errs, &RuleError{Index: i, Rule: s, Err: err})
		}
	}
	return c.finish(), errors.Join(errs...)
}

// MustCompile is Compile that panics if a rule is invalid.
func MustCompile(rules []string, opts Options) *Matcher {
	m, err := Compile(rules, opts)
	if err != nil {
		panic(err)
	}
	return m
}

// Match reports whether addr matches: its host, as HostOf extracts it, is
// matched as an IP address or else as a domain name.
func (m *Matcher) Match(addr string) bool {
	host, ip, isIP := readTarget(addr)
	if isIP {
		return m.MatchIP(ip)
	}
	return m.matchDomain(host)
}

// MatchNetAddr is Match for a net.Addr, such as a connection's RemoteAddr:
// *net.TCPAddr, *net.UDPAddr and *net.IPAddr are matched by IP address
// without formatting them, Unix socket addresses match no rule, and other
// addresses are matched by their String.
func (m *Matcher) MatchNetAddr(a net.Addr) bool {
	if ip, ok := netAddrIP(a); ok {
		return m.MatchIP(ip)
	}
	switch a.(type) {
	case nil, *net.UnixAddr:
		return false
	}
	return m.Match(a.String())
}

// netAddrIP returns the IP address of an IP net.Addr.
func netAddrIP(a net.Addr) (netip.Addr, bool) {
	switch a := a.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr(), true
	case *net.UDPAddr:
		return a.AddrPort().Addr(), true
	case *net.IPAddr:
		if a == nil {
			return netip.Addr{}, true
		}
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip, true
	}
	return netip.Addr{}, false
}

// readTarget reads the host of addr, and its IP address if it is one.
func readTarget(addr string) (host string, ip netip.Addr, isIP bool) {
	host, numeric := addr, false
	if plain, num := hostClass(addr); plain {
		numeric = num
	} else {
		host = HostOf(addr)
		numeric = strings.IndexByte(host, ':') >= 0 || strings.Trim(host, "0123456789.") == ""
	}
	if numeric {
		if ip, err := netip.ParseAddr(host); err == nil {
			return host, ip.Unmap().WithZone(""), true
		}
	}
	return host, netip.Addr{}, false
}

// parseIP parses host as an IP address, without building an error for the
// common case of a domain name.
func parseIP(host string) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	if strings.IndexByte(host, ':') < 0 {
		for i := range len(host) {
			if c := host[i]; (c < '0' || c > '9') && c != '.' {
				return netip.Addr{}, false
			}
		}
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}

// MatchIP reports whether ip matches an IP rule. IPv4-mapped IPv6 addresses
// match as IPv4.
func (m *Matcher) MatchIP(ip netip.Addr) bool {
	if m == nil || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap().WithZone("")
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

// MatchDomain reports whether host, a domain name or host:port, matches a
// domain rule. IP addresses match no domain rule. Rules and hosts are ASCII:
// write internationalized names in their xn-- (punycode) form.
func (m *Matcher) MatchDomain(host string) bool {
	if plain, numeric := hostClass(host); !plain || numeric {
		host = HostOf(host)
		if _, ok := parseIP(host); ok {
			return false
		}
	}
	return m.matchDomain(host)
}

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

type compiler struct {
	geo      *GeoData
	ips      ipSetBuilder
	geoIPs   []*ipSet
	inverse  []*ipSet
	domains  domainSet
	sites    []*domainSet
	ipRules  int
	domRules int
	probes   []probe
}

func newCompiler(opts Options) *compiler {
	c := &compiler{geo: opts.GeoData}
	if c.geo == nil {
		c.geo = &GeoData{}
	}
	return c
}

func (c *compiler) finish() *Matcher {
	// Several geo entries become one set, so that a query looks once.
	if len(c.geoIPs) > 1 {
		c.geoIPs = []*ipSet{c.geo.mergedIPs(c.geoIPs)}
	}
	if len(c.sites) > 1 {
		c.sites = []*domainSet{c.geo.mergedSites(c.sites)}
	}
	m := &Matcher{
		ipSets:   c.geoIPs,
		inverse:  c.inverse,
		domSets:  c.sites,
		ipRules:  c.ipRules,
		domRules: c.domRules,
		probes:   c.probes,
	}
	if own := c.ips.build(); own.ranges() > 0 {
		m.ipSets = append([]*ipSet{own}, m.ipSets...)
	}
	if c.domains.finish(); c.domains.active {
		m.domSets = append([]*domainSet{&c.domains}, m.domSets...)
	}
	return m
}

// add compiles a parsed rule.
func (c *compiler) add(r Rule) error {
	p := probe{rule: r}
	switch r.Kind {
	case RuleIP:
		c.ips.addPrefix(r.Prefix)
		c.ipRules++
	case RuleGeoIP, RuleGeoSite, RuleExt:
		geo, site, err := c.geo.compiledRule(r)
		if err != nil {
			return err
		}
		if geo != nil {
			c.addGeoIPSet(geo, r.Negate)
		} else {
			c.addSiteSet(site)
		}
		p.geo, p.site = geo, site
	case RuleFull:
		c.domains.addName(r.Value, nameExact)
		c.domRules++
	case RuleDomain:
		c.domains.addName(r.Value, nameExact|nameSub)
		c.domRules++
	case RuleSubdomain:
		c.domains.addName(r.Value, nameSub)
		c.domRules++
	case RuleKeyword:
		c.domains.addKeyword(r.Value)
		c.domRules++
	case RuleRegexp:
		if err := c.domains.addRegexp(r.Value); err != nil {
			return err
		}
		c.domRules++
	case RuleDotless:
		if r.Value == "" {
			c.domains.dotlessAny = true
		} else {
			c.domains.dotless = append(c.domains.dotless, r.Value)
		}
		c.domRules++
	default:
		return fmt.Errorf("unknown rule kind %d", r.Kind)
	}
	c.probes = append(c.probes, p)
	return nil
}

func (c *compiler) addGeoIPSet(geo *geoIPSet, negate bool) {
	list := &c.geoIPs
	if negate != geo.inverse {
		list = &c.inverse
	}
	if !slices.Contains(*list, geo.set) {
		*list = append(*list, geo.set)
	}
	c.ipRules++
}

func (c *compiler) addSiteSet(site *domainSet) {
	if !slices.Contains(c.sites, site) {
		c.sites = append(c.sites, site)
	}
	c.domRules++
}

// filterAttrs returns the domains that have every attribute in attrs.
func filterAttrs(domains []Domain, attrs []string) []Domain {
	if len(attrs) == 0 {
		return domains
	}
	var out []Domain
next:
	for _, d := range domains {
		for _, a := range attrs {
			if !slices.Contains(d.Attrs, a) {
				continue next
			}
		}
		out = append(out, d)
	}
	return out
}
