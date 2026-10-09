package geomatch

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RuleError reports a rule that Compile skipped.
type RuleError struct {
	Rule string
	Err  error
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("geomatch: rule %q: %v", e.Rule, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

var (
	errEmptyValue = errors.New("empty value")
	errNotHost    = errors.New("not an IP address, CIDR or domain")
	errWildcard   = errors.New("a wildcard must be a leading * of a domain or trailing octets of an IPv4 address")
)

// Options configures Compile.
type Options struct {
	// GeoData reads geoip:, geosite: and ext: rules. Nil reads only ext:
	// files, relative to the working directory; geoip:private still works.
	GeoData *GeoData
}

// Matcher matches IP addresses and domain names against compiled rules. It
// is immutable and safe for concurrent use. A nil *Matcher matches nothing.
type Matcher struct {
	ips      ipSet
	inverse  []*ipSet // geoip:!code and reverse_match entries
	domains  domainSet
	ipRules  int
	domRules int
}

// SplitRules splits text into rules, one per line, trimming spaces and
// dropping empty lines. Comments are kept for Compile to skip.
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
	c := compiler{geo: opts.GeoData}
	if c.geo == nil {
		c.geo = &GeoData{}
	}
	var errs []error
	for _, rule := range rules {
		rule = strings.TrimSpace(strings.ReplaceAll(rule, "：", ":"))
		if rule == "" || rule[0] == '#' || rule[0] == ';' {
			continue
		}
		if err := c.add(rule); err != nil {
			errs = append(errs, &RuleError{Rule: rule, Err: err})
		}
	}
	c.domains.finish()
	m := &Matcher{domains: c.domains, ipRules: c.ipRules, domRules: c.domRules}
	m.ips = *c.ips.build()
	for i := range c.inverse {
		m.inverse = append(m.inverse, c.inverse[i].build())
	}
	return m, errors.Join(errs...)
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
	host := HostOf(addr)
	if ip, ok := parseIP(host); ok {
		return m.MatchIP(ip)
	}
	return m.matchDomain(host)
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
	if m.ips.contains(ip) {
		return true
	}
	for _, s := range m.inverse {
		if !s.contains(ip) {
			return true
		}
	}
	return false
}

// MatchDomain reports whether host, a domain name or host:port, matches a
// domain rule. IP addresses match no domain rule.
func (m *Matcher) MatchDomain(host string) bool {
	host = HostOf(host)
	if _, ok := parseIP(host); ok {
		return false
	}
	return m.matchDomain(host)
}

func (m *Matcher) matchDomain(host string) bool {
	return m != nil && m.domains.match(host)
}

// Len returns the number of rules compiled into m.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return m.ipRules + m.domRules
}

// HasIPRules and HasDomainRules report which kinds of rules m holds, for
// callers that only see one kind of address.
func (m *Matcher) HasIPRules() bool { return m != nil && m.ipRules > 0 }

// HasDomainRules reports whether m holds domain rules.
func (m *Matcher) HasDomainRules() bool { return m != nil && m.domRules > 0 }

type compiler struct {
	geo      *GeoData
	ips      ipSetBuilder
	inverse  []ipSetBuilder
	domains  domainSet
	ipRules  int
	domRules int
}

func (c *compiler) add(rule string) error {
	if kind, value, ok := strings.Cut(rule, ":"); ok {
		switch strings.ToLower(kind) {
		case "geoip":
			return c.addGeoIP("", value)
		case "ext-ip":
			file, code, err := splitExt(value)
			if err != nil {
				return err
			}
			return c.addGeoIP(c.geo.rulePath(file, c.geo.IPFile), code)
		case "geosite":
			return c.addGeoSite("", value)
		case "ext-domain":
			file, code, err := splitExt(value)
			if err != nil {
				return err
			}
			return c.addGeoSite(c.geo.rulePath(file, c.geo.SiteFile), code)
		case "ext":
			return c.addExt(value)
		case "full", "domain", "keyword", "regexp", "dotless":
			return c.addDomainRule(strings.ToLower(kind), strings.TrimSpace(value))
		}
	}
	return c.addPlain(rule)
}

// addPlain adds an IP address, a CIDR, an IPv4 wildcard, a *-prefixed domain
// suffix or a plain domain, which matches as a keyword.
func (c *compiler) addPlain(rule string) error {
	if p, ok, err := parseIPv4Wildcard(rule); ok || err != nil {
		if err != nil {
			return err
		}
		c.ips.addPrefix(p)
		c.ipRules++
		return nil
	}
	if strings.Contains(rule, "/") && !strings.Contains(rule, "://") {
		p, err := netip.ParsePrefix(rule)
		if err != nil {
			return err
		}
		c.ips.addPrefix(p.Masked())
		c.ipRules++
		return nil
	}
	if suffix, ok := strings.CutPrefix(rule, "*"); ok {
		flags := uint8(suffixSelf | suffixSub)
		if s, ok := strings.CutPrefix(suffix, "."); ok {
			suffix, flags = s, suffixSub
		}
		host, err := domainValue(suffix)
		if err != nil {
			return err
		}
		c.domains.addSuffix(host, flags)
		c.domRules++
		return nil
	}
	if strings.Contains(rule, "*") {
		return errWildcard
	}
	host := HostOf(rule)
	if ip, err := netip.ParseAddr(host); err == nil {
		c.ips.addAddr(ip)
		c.ipRules++
		return nil
	}
	host, err := domainValue(host)
	if err != nil {
		return err
	}
	c.domains.addKeyword(host)
	c.domRules++
	return nil
}

func (c *compiler) addDomainRule(kind, value string) error {
	switch kind {
	case "regexp":
		if value == "" {
			return errEmptyValue
		}
		if err := c.domains.addRegexp(value); err != nil {
			return err
		}
	case "dotless":
		if value == "" {
			c.domains.dotlessAny = true
			break
		}
		if strings.Contains(value, ".") {
			return errors.New("dotless value contains a dot")
		}
		text, err := keywordValue(value)
		if err != nil {
			return err
		}
		c.domains.dotless = append(c.domains.dotless, text)
	case "keyword":
		text, err := keywordValue(value)
		if err != nil {
			return err
		}
		c.domains.addKeyword(text)
	default:
		host, err := domainValue(value)
		if err != nil {
			return err
		}
		if kind == "full" {
			c.domains.addFull(host)
		} else {
			c.domains.addSuffix(host, suffixSelf|suffixSub)
		}
	}
	c.domRules++
	return nil
}

// addGeoIP adds code, or the addresses outside it for !code.
func (c *compiler) addGeoIP(file, code string) error {
	code = strings.TrimSpace(code)
	negate := strings.HasPrefix(code, "!")
	if negate {
		code = strings.TrimSpace(code[1:])
	}
	if code == "" {
		return errEmptyValue
	}
	geo, err := c.geo.LoadIP(file, code)
	if err != nil {
		return err
	}
	c.addGeoIPEntry(geo, negate)
	return nil
}

func (c *compiler) addGeoIPEntry(geo GeoIP, negate bool) {
	b := &c.ips
	if negate != geo.Inverse {
		c.inverse = append(c.inverse, ipSetBuilder{})
		b = &c.inverse[len(c.inverse)-1]
	}
	for _, p := range geo.Prefixes {
		b.addPrefix(p)
	}
	c.ipRules++
}

// addGeoSite adds code, optionally followed by @attributes that every entry
// added must have.
func (c *compiler) addGeoSite(file, value string) error {
	code, attrs, err := splitAttrs(value)
	if err != nil {
		return err
	}
	domains, err := c.geo.LoadSite(file, code)
	if err != nil {
		return err
	}
	c.domains.addDomains(filterAttrs(domains, attrs))
	c.domRules++
	return nil
}

// addExt adds file:code from a geoip or geosite file.
func (c *compiler) addExt(value string) error {
	file, code, err := splitExt(value)
	if err != nil {
		return err
	}
	negate := strings.HasPrefix(code, "!")
	if negate {
		code = strings.TrimSpace(code[1:])
	}
	code, attrs, err := splitAttrs(code)
	if err != nil {
		return err
	}
	path := c.geo.rulePath(file, cmpOr(c.geo.SiteFile, c.geo.IPFile))
	geo, domains, isIP, err := c.geo.load(path, code, kindAny)
	switch {
	case err != nil:
		return err
	case isIP:
		if len(attrs) > 0 {
			return errors.New("attributes on a geoip entry")
		}
		c.addGeoIPEntry(geo, negate)
	case negate:
		return errors.New("! on a geosite entry")
	default:
		c.domains.addDomains(filterAttrs(domains, attrs))
		c.domRules++
	}
	return nil
}

// splitExt splits file:code at the last colon, since a code has none and a
// Windows path such as C:\geo\site.dat does.
func splitExt(value string) (file, code string, err error) {
	value = strings.TrimSpace(value)
	i := strings.LastIndexByte(value, ':')
	if i < 0 {
		return "", "", errors.New("want file:code")
	}
	file, code = strings.TrimSpace(value[:i]), strings.TrimSpace(value[i+1:])
	if file == "" || code == "" {
		return "", "", errors.New("want file:code")
	}
	return file, code, nil
}

// splitAttrs splits code@attr@attr.
func splitAttrs(value string) (code string, attrs []string, err error) {
	parts := strings.Split(value, "@")
	code = strings.TrimSpace(parts[0])
	if code == "" {
		return "", nil, errEmptyValue
	}
	for _, a := range parts[1:] {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			attrs = append(attrs, a)
		}
	}
	return code, attrs, nil
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
			if !containsString(d.Attrs, a) {
				continue next
			}
		}
		out = append(out, d)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// domainValue normalizes the domain of a full:, domain: or *-prefixed rule:
// lowercase, without a trailing dot, and nothing that cannot be part of a
// host name.
func domainValue(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	switch {
	case host == "":
		return "", errEmptyValue
	case strings.ContainsAny(host, " \t/?#@:%*[]"):
		return "", errNotHost
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", errors.New("an IP address in a domain rule")
	}
	return host, nil
}

// keywordValue normalizes the text of a keyword: or dotless: rule, which is
// matched as given, lowercase.
func keywordValue(value string) (string, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	switch {
	case text == "":
		return "", errEmptyValue
	case strings.ContainsAny(text, " \t"):
		return "", errors.New("spaces in a keyword")
	}
	return text, nil
}

// parseIPv4Wildcard parses an IPv4 address whose trailing octets are *, such
// as 10.* or 192.168.*.*. It reports whether rule looked like one.
func parseIPv4Wildcard(rule string) (netip.Prefix, bool, error) {
	if !strings.HasSuffix(rule, "*") || strings.ContainsAny(rule, ":/") || strings.HasPrefix(rule, "*") {
		return netip.Prefix{}, false, nil
	}
	parts := strings.Split(rule, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return netip.Prefix{}, false, nil
	}
	var octets [4]byte
	fixed := 0
	for i, part := range parts {
		if part == "*" {
			continue
		}
		if fixed != i {
			return netip.Prefix{}, true, errWildcard
		}
		v, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			// Not an address: a domain such as example.* is not supported.
			return netip.Prefix{}, false, nil
		}
		octets[i] = byte(v)
		fixed++
	}
	if fixed == 0 {
		return netip.Prefix{}, true, errWildcard
	}
	return netip.PrefixFrom(netip.AddrFrom4(octets), fixed*8), true, nil
}
