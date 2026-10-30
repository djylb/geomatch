package geomatch

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RuleKind is the kind of a Rule.
type RuleKind uint8

// Rule kinds. The zero RuleKind is not a rule.
const (
	// RuleIP matches the addresses of Prefix: an address, a CIDR prefix or
	// an IPv4 wildcard such as 10.*.
	RuleIP RuleKind = iota + 1
	// RuleGeoIP matches the addresses of a geoip entry, or those outside it
	// with Negate.
	RuleGeoIP
	// RuleFull matches the host Value exactly.
	RuleFull
	// RuleDomain matches Value and its subdomains.
	RuleDomain
	// RuleSubdomain matches the subdomains of Value only.
	RuleSubdomain
	// RuleKeyword matches hosts containing Value.
	RuleKeyword
	// RuleRegexp matches hosts matching the regular expression Value,
	// regardless of case.
	RuleRegexp
	// RuleDotless matches hosts without a dot that contain Value, or all of
	// them when Value is empty.
	RuleDotless
	// RuleGeoSite matches the domains of a geosite entry.
	RuleGeoSite
	// RuleExt matches an entry of File, which may be a geoip or a geosite
	// file.
	RuleExt
	// RulePort matches every IP address and domain name on Ports, as in
	// *:25 or *:8000-9000; without Ports it means every port.
	RulePort
)

// String returns the name of k, the prefix of its rules: ip, geoip, full,
// domain, subdomain, keyword, regexp, dotless, geosite or ext.
func (k RuleKind) String() string {
	names := [...]string{RuleIP: "ip", RuleGeoIP: "geoip", RuleFull: "full", RuleDomain: "domain",
		RuleSubdomain: "subdomain", RuleKeyword: "keyword", RuleRegexp: "regexp", RuleDotless: "dotless",
		RuleGeoSite: "geosite", RuleExt: "ext", RulePort: "port"}
	if int(k) < len(names) && names[k] != "" {
		return names[k]
	}
	return "kind " + strconv.Itoa(int(k))
}

// Rule is a parsed rule. ParseRule returns rules in a normal form: lowercase
// domains, codes with upper-case ASCII letters, sorted attributes and masked
// prefixes, so that String gives a rule one spelling however it was written.
//
// A Rule reads and writes itself as text, so that configuration can hold
// []Rule, checked as it is decoded, for CompileRules.
type Rule struct {
	Kind RuleKind
	// Prefix is the address range of RuleIP, or with Last the first address
	// of its range.
	Prefix netip.Prefix
	// Last, if valid, is the last address of a RuleIP that holds the
	// addresses from Prefix, a single address, to Last, as in
	// 10.0.0.1-10.0.0.50. A range that is a CIDR prefix is written as the
	// prefix instead.
	Last netip.Addr
	// Value is the domain, text or regular expression of the domain kinds.
	Value string
	// File is the geodata file of RuleExt, and of RuleGeoIP and RuleGeoSite
	// when they name one (ext-ip: and ext-domain:); empty means the default
	// file of GeoData.
	File string
	// Code is the upper-case code of the geo kinds.
	Code string
	// Attrs are the attributes that every domain of a geosite entry must
	// have, lowercase and sorted.
	Attrs []string
	// Negate inverts a geoip entry: the rule matches the addresses outside it.
	Negate bool
	// Plain marks a domain written without a kind, such as example.com,
	// whose kind the PlainDomain of the Compiler that compiles it decides:
	// String writes it without a kind again, so that a rule decoded from
	// configuration, as JSON, keeps its meaning for any Compiler. ParseRule
	// reads it as RuleKeyword, as rule lists mean it.
	Plain bool
	// Ports, if any, are the ports the rule matches, sorted and merged;
	// none means every port, but for RulePort. Regexp: and ext rules have
	// none. See Matcher for how queries without a port match them. The rules that Find and Decide return share it with
	// their Matcher, so that they do not allocate: copy it to change it.
	Ports []PortRange
}

var (
	errNoRule     = classed("empty rule or comment", ErrInvalidRule)
	errEmptyValue = errors.New("empty value")
	errNotHost    = errors.New("not an IP address, CIDR or domain")
	errWildcard   = errors.New("a wildcard must be a leading * of a domain or trailing octets of an IPv4 address")
	errNonASCII   = errors.New("non-ASCII text, which no host matches as hosts are matched in their xn-- form; write that form")
)

// trimRule trims spaces around a rule, and the byte order mark that text
// saved by some editors starts with.
func trimRule(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' })
}

// SplitLines splits text into lines for Compile or ParseRules, keeping their
// positions, so that RuleError.Index+1 is the line number. Lines may end in
// \n, \r\n or \r, and a byte order mark at the start is dropped; Compile
// skips the empty lines and comments.
func SplitLines(text string) []string {
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n")
}

// isComment reports whether s is empty or a comment, starting with # or ;.
func isComment(s string) bool {
	s = trimRule(s)
	return s == "" || s[0] == '#' || s[0] == ';'
}

// parseRule parses s, reading a domain without a kind as a rule of kind
// plain: RuleKeyword, RuleDomain or RuleFull.
func parseRule(s string, plain RuleKind) (Rule, error) {
	r, err := parsePortRule(trimRule(strings.ReplaceAll(s, "：", ":")), plain)
	var se *SyntaxError
	if errors.As(err, &se) {
		// The offset in the rule as written, where a full-width colon
		// takes three bytes.
		orig, off := trimRule(s), 0
		for j := 0; j < se.Offset && off < len(orig); j++ {
			if strings.HasPrefix(orig[off:], "：") {
				off += len("：")
			} else {
				off++
			}
		}
		se.Offset = off
	}
	return r, err
}

// parsePortRule parses s, trimmed and with full-width colons read: the
// rules of parseClassic, with ports after those that can have them, address
// ranges and port rules.
func parsePortRule(s string, plain RuleKind) (Rule, error) {
	if isComment(s) {
		return Rule{}, errNoRule
	}
	kind, value, ok := strings.Cut(s, ":")
	if ok {
		switch strings.ToLower(kind) {
		case "geoip", "geosite", "full", "domain", "keyword", "dotless":
			value, ports, hasPorts := strings.Cut(value, ":")
			r, err := parseClassic(kind+":"+value, plain)
			if err != nil || !hasPorts {
				return r, err
			}
			return withPorts(r, ports, true, len(kind)+len(value)+2)
		case "regexp", "ext", "ext-ip", "ext-domain":
			return parseClassic(s, plain)
		}
		if strings.Count(s, ":") == 1 && isKindName(kind) && !isPortList(value) && !strings.HasPrefix(value, "//") {
			return Rule{}, fmt.Errorf("unknown rule kind %q", kind)
		}
	}
	return parsePlainPorts(s, plain)
}

// isRuleKind reports whether s, lowercase, is the kind of a rule.
func isRuleKind(s string) bool {
	switch s {
	case "geoip", "ext-ip", "geosite", "ext-domain", "ext", "full", "domain", "keyword", "regexp", "dotless":
		return true
	}
	return false
}

// isPortList reports whether s looks like a port list, as after host: in
// host:80,443 or host:8000-9000.
func isPortList(s string) bool {
	return s != "" && strings.Trim(s, "0123456789,- \t") == ""
}

// parsePlainPorts parses a rule without a kind, with its ports.
func parsePlainPorts(s string, plain RuleKind) (Rule, error) {
	if strings.HasPrefix(s, "//") || strings.Contains(s, "://") {
		// A URL: its host, as before, and its port if it has one.
		r, err := parsePlain(s, plain)
		if err != nil {
			return r, err
		}
		_, port, off := portText(s)
		if err := checkPlainText(r, port != ""); err != nil {
			return Rule{}, err
		}
		if port != "" && port[0] != ':' {
			return Rule{}, syntaxErr(off, "unexpected text after ]")
		}
		return withPorts(r, strings.TrimPrefix(port, ":"), port != "", off+1)
	}
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return Rule{}, syntaxErr(0, "[ without ]")
		}
		r, err := parseAddrRange(s[1:end], 1)
		if err != nil {
			return r, err
		}
		switch rest := s[end+1:]; {
		case rest == "":
			return r, nil
		case rest[0] == ':':
			return withPorts(r, rest[1:], true, end+2)
		default:
			return Rule{}, syntaxErr(end+1, "unexpected text after ]")
		}
	}
	addr, ports, has := s, "", false
	switch n := strings.Count(s, ":"); {
	case n == 1:
		addr, ports, has = strings.Cut(s, ":")
		if strings.TrimSpace(addr) == "*" {
			// A port rule: every address on the ports.
			r, err := withPorts(Rule{Kind: RulePort}, ports, true, len(addr)+1)
			if err == nil && r.Ports == nil {
				r.Ports = allPorts
			}
			return r, err
		}
	case n > 1:
		// A bare IPv6 address, prefix or range, which has no port.
		r, err := parseAddrRange(s, 0)
		if err != nil {
			i := strings.LastIndexByte(s, ':')
			if _, e := parseAddrRange(s[:i], 0); e == nil && isPortList(s[i+1:]) {
				return Rule{}, syntaxErr(i, "ports after an IPv6 address need brackets: [%s]:%s", s[:i], s[i+1:])
			}
		}
		return r, err
	}
	var r Rule
	var err error
	if isAddrRange(addr) {
		r, err = parseAddrRange(addr, 0)
	} else {
		r, err = parsePlain(addr, plain)
	}
	if err != nil {
		return r, err
	}
	if err := checkPlainText(r, has); err != nil {
		return Rule{}, err
	}
	return withPorts(r, ports, has, len(addr)+1)
}

// checkPlainText rejects a domain without a kind that, written with
// ports if it has them, would read as another rule.
func checkPlainText(r Rule, ports bool) error {
	switch {
	case !r.Plain:
	case isAddrRange(r.text()):
		// An address before a -, as 10.0.0.1-x, is a range that does not
		// parse, rather than a host.
		return syntaxErr(0, "invalid address range %q", r.text())
	case ports && isRuleKind(r.text()):
		return syntaxErr(0, "host %q with ports is a rule kind; write it with a kind, as keyword:%s:", r.Value, r.Value)
	}
	return nil
}

// isAddrRange reports whether s is meant as an address range: an IP
// address before a -.
func isAddrRange(s string) bool {
	from, _, ok := strings.Cut(s, "-")
	if !ok || strings.Contains(s, "/") {
		return false
	}
	_, err := netip.ParseAddr(strings.TrimSpace(from))
	return err == nil
}

// parseAddrRange parses an IP address, a CIDR prefix or a range of
// addresses first-last, which starts at byte off of the rule.
func parseAddrRange(s string, off int) (Rule, error) {
	if from, to, ok := strings.Cut(s, "-"); ok {
		first, err := parseRangeAddr(from, off)
		if err != nil {
			return Rule{}, err
		}
		last, err := parseRangeAddr(to, off+len(from)+1)
		if err != nil {
			return Rule{}, err
		}
		r, err := rangeRule(first, last)
		if err != nil {
			return Rule{}, syntaxErr(off, "%v", err)
		}
		return r, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Rule{}, syntaxErr(off, "invalid CIDR prefix %q", s)
		}
		return Rule{Kind: RuleIP, Prefix: normalPrefix(p)}, nil
	}
	ip, err := parseRangeAddr(s, off)
	if err != nil {
		return Rule{}, err
	}
	return Rule{Kind: RuleIP, Prefix: netip.PrefixFrom(ip, ip.BitLen())}, nil
}

// parseRangeAddr parses an address of a range, with spaces around it and
// an IPv6 zone, which is dropped, at byte off of the rule.
func parseRangeAddr(s string, off int) (netip.Addr, error) {
	t := strings.TrimLeft(s, " \t")
	off += len(s) - len(t)
	t = strings.TrimRight(t, " \t")
	ip, err := netip.ParseAddr(t)
	if err != nil {
		if i := strings.LastIndexByte(t, '%'); i > 0 {
			// A zone percent-encoded, as in [fe80::1%25eth0].
			ip, err = netip.ParseAddr(t[:i])
		}
		if err != nil {
			return netip.Addr{}, syntaxErr(off, "invalid IP address %q", t)
		}
	}
	return normalAddr(ip), nil
}

// withPorts sets the ports of r, written as text at byte off of the rule,
// if has.
func withPorts(r Rule, text string, has bool, off int) (Rule, error) {
	if !has {
		return r, nil
	}
	ports, err := parsePorts(text, off)
	if err != nil {
		return Rule{}, err
	}
	r.Ports = ports
	return r, nil
}

// parseClassic parses s without its ports, address ranges and port rules,
// which parsePortRule reads, reading a domain without a kind as a rule of
// kind plain.
func parseClassic(s string, plain RuleKind) (Rule, error) {
	s = trimRule(strings.ReplaceAll(s, "：", ":"))
	if isComment(s) {
		return Rule{}, errNoRule
	}
	kind, value, ok := strings.Cut(s, ":")
	if !ok {
		return parsePlain(s, plain)
	}
	switch strings.ToLower(kind) {
	case "geoip":
		code, negate, err := parseCode(value)
		return Rule{Kind: RuleGeoIP, Code: code, Negate: negate}, err
	case "ext-ip":
		file, rest, err := splitExt(value)
		if err != nil {
			return Rule{}, err
		}
		code, negate, err := parseCode(rest)
		return Rule{Kind: RuleGeoIP, File: file, Code: code, Negate: negate}, err
	case "geosite":
		code, attrs, err := splitAttrs(value)
		return Rule{Kind: RuleGeoSite, Code: code, Attrs: attrs}, err
	case "ext-domain":
		file, rest, err := splitExt(value)
		if err != nil {
			return Rule{}, err
		}
		code, attrs, err := splitAttrs(rest)
		return Rule{Kind: RuleGeoSite, File: file, Code: code, Attrs: attrs}, err
	case "ext":
		file, rest, err := splitExt(value)
		if err != nil {
			return Rule{}, err
		}
		rest, negate := strings.CutPrefix(rest, "!")
		code, attrs, err := splitAttrs(rest)
		if err == nil && negate && len(attrs) > 0 {
			err = errors.New("! with attributes")
		}
		return Rule{Kind: RuleExt, File: file, Code: code, Attrs: attrs, Negate: negate}, err
	case "full", "domain":
		host, err := domainValue(value)
		k := RuleFull
		if strings.EqualFold(kind, "domain") {
			k = RuleDomain
		}
		return Rule{Kind: k, Value: host}, err
	case "keyword":
		text, err := keywordValue(value)
		return Rule{Kind: RuleKeyword, Value: text}, err
	case "regexp":
		pattern := strings.TrimSpace(value)
		if pattern == "" {
			return Rule{}, errEmptyValue
		}
		if !isASCII(pattern) {
			return Rule{}, errNonASCII
		}
		// Parsed, which is all of compiling that can fail, as written
		// first, so that errors quote the pattern without the (?i) that
		// matching adds; the builder compiles it once.
		if _, err := syntax.Parse(pattern, syntax.Perl); err != nil {
			return Rule{}, err
		}
		if _, err := syntax.Parse("(?i)"+pattern, syntax.Perl); err != nil {
			return Rule{}, err
		}
		return Rule{Kind: RuleRegexp, Value: pattern}, nil
	case "dotless":
		value = strings.TrimSpace(value)
		if value == "" {
			return Rule{Kind: RuleDotless}, nil
		}
		if strings.Contains(value, ".") {
			return Rule{}, errors.New("dotless value contains a dot")
		}
		text, err := keywordValue(value)
		return Rule{Kind: RuleDotless, Value: text}, err
	}
	// A word before a single colon is a misspelt kind, such as ful:x.com,
	// unless a port or a scheme-relative URL follows it, as in host:443.
	if strings.Count(s, ":") == 1 && isKindName(kind) && !isPort(value) && !strings.HasPrefix(value, "//") {
		return Rule{}, fmt.Errorf("unknown rule kind %q", kind)
	}
	return parsePlain(s, plain)
}

// isKindName reports whether s could be the kind of a rule: letters, digits,
// - and _, with a letter.
func isKindName(s string) bool {
	letter := false
	for i := range len(s) {
		switch c := s[i] | 0x20; {
		case c >= 'a' && c <= 'z':
			letter = true
		case s[i] >= '0' && s[i] <= '9', s[i] == '-', s[i] == '_':
		default:
			return false
		}
	}
	return letter
}

// isPort reports whether s starts with a port number, as after host: in
// host:port or host:port/path.
func isPort(s string) bool {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// parsePlain parses a rule without a kind: an IP address, a CIDR, an IPv4
// wildcard, a *-prefixed domain or a plain domain, which is a rule of kind
// plain.
func parsePlain(s string, plain RuleKind) (Rule, error) {
	if p, ok, err := parseIPv4Wildcard(s); ok || err != nil {
		return Rule{Kind: RuleIP, Prefix: p}, err
	}
	if strings.Contains(s, "/") && !strings.Contains(s, "://") && !strings.HasPrefix(s, "//") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Rule{}, err
		}
		return Rule{Kind: RuleIP, Prefix: normalPrefix(p)}, nil
	}
	if suffix, ok := strings.CutPrefix(s, "*"); ok {
		k := RuleDomain
		if rest, ok := strings.CutPrefix(suffix, "."); ok {
			suffix, k = rest, RuleSubdomain
		}
		host, err := domainValue(suffix)
		return Rule{Kind: k, Value: host}, err
	}
	if strings.Contains(s, "*") {
		return Rule{}, errWildcard
	}
	if from, to, ok := strings.Cut(s, "-"); ok {
		if _, err := netip.ParseAddr(strings.TrimSpace(from)); err == nil {
			if _, err := netip.ParseAddr(strings.TrimSpace(to)); err == nil {
				return Rule{}, errors.New("IP ranges are not supported; write CIDR prefixes")
			}
		}
	}
	host := HostOf(s)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = normalAddr(ip)
		return Rule{Kind: RuleIP, Prefix: netip.PrefixFrom(ip, ip.BitLen())}, nil
	}
	// A leading dot, as in ".example.com", means the subdomains: a keyword
	// keeps it, so that it does not match the domain itself.
	rest, dotted := strings.CutPrefix(host, ".")
	host, err := domainValue(rest)
	switch {
	case plain == RuleKeyword && dotted:
		return Rule{Kind: RuleKeyword, Value: "." + host, Plain: true}, err
	case plain == RuleKeyword:
		return Rule{Kind: RuleKeyword, Value: host, Plain: true}, err
	case dotted:
		return Rule{Kind: RuleSubdomain, Value: host, Plain: true}, err
	default:
		return Rule{Kind: plain, Value: host, Plain: true}, err
	}
}

// normalPrefix masks p and writes an IPv4-mapped prefix as IPv4.
func normalPrefix(p netip.Prefix) netip.Prefix {
	addr, bits := p.Addr().WithZone(""), p.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr, bits = addr.Unmap(), bits-96
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// String returns the rule in the syntax ParseRule reads, or "" for the zero
// Rule.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) String() string {
	if r.Kind == RulePort {
		ports := r.Ports
		if len(ports) == 0 {
			ports = allPorts
		}
		return "*:" + portsText(ports)
	}
	s := r.text()
	if len(r.Ports) == 0 || s == "" {
		return s
	}
	if r.Kind == RuleIP && r.Prefix.Addr().Is6() {
		s = "[" + s + "]"
	}
	return s + ":" + portsText(r.Ports)
}

// text returns the rule without its ports.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) text() string {
	code := lowerASCII(r.Code)
	if r.Negate {
		code = "!" + code
	}
	for _, a := range r.Attrs {
		code += "@" + a
	}
	if r.Plain {
		// Without a kind, as written, for the PlainDomain of the Compiler.
		switch r.Kind {
		case RuleKeyword, RuleDomain, RuleFull:
			return r.Value
		case RuleSubdomain:
			return "." + r.Value
		case RuleIP, RuleGeoIP, RuleRegexp, RuleDotless, RuleGeoSite, RuleExt, RulePort:
			// Never plain: written with their kind below.
		}
	}
	switch r.Kind {
	case RuleIP:
		if r.Last.IsValid() {
			return r.Prefix.Addr().String() + "-" + r.Last.String()
		}
		if r.Prefix.IsSingleIP() {
			return r.Prefix.Addr().String()
		}
		return r.Prefix.String()
	case RuleGeoIP:
		if r.File != "" {
			return "ext-ip:" + r.File + ":" + code
		}
		return "geoip:" + code
	case RuleGeoSite:
		if r.File != "" {
			return "ext-domain:" + r.File + ":" + code
		}
		return "geosite:" + code
	case RuleExt:
		return "ext:" + r.File + ":" + code
	case RuleFull:
		return "full:" + r.Value
	case RuleDomain:
		return "domain:" + r.Value
	case RuleSubdomain:
		return "*." + r.Value
	case RuleKeyword:
		return "keyword:" + r.Value
	case RuleRegexp:
		return "regexp:" + r.Value
	case RuleDotless:
		return "dotless:" + r.Value
	case 0:
		return ""
	default:
		return "rule kind " + strconv.Itoa(int(r.Kind))
	}
}

// IsIP reports whether the rule matches IP addresses. RuleExt depends on its
// file, so it counts as both kinds.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) IsIP() bool {
	return r.Kind == RuleIP || r.Kind == RuleGeoIP || r.Kind == RuleExt || r.Kind == RulePort
}

// IsDomain reports whether the rule matches domain names.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) IsDomain() bool {
	return r.Kind >= RuleFull && r.Kind <= RulePort
}

// MarshalText returns the rule as String writes it, or an error for the
// zero Rule or an unknown kind.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rule) MarshalText() ([]byte, error) {
	if r.Kind < RuleIP || r.Kind > RulePort {
		return nil, fmt.Errorf("geomatch: cannot write rule kind %d", r.Kind)
	}
	return []byte(r.String()), nil
}

// UnmarshalText sets r to the rule that ParseRule reads from text.
//
//goland:noinspection GoMixedReceiverTypes
func (r *Rule) UnmarshalText(text []byte) error {
	rule, err := ParseRule(string(text))
	if err != nil {
		return err
	}
	*r = rule
	return nil
}

// parseCode parses a geoip code, which ! negates.
func parseCode(value string) (code string, negate bool, err error) {
	value = strings.TrimSpace(value)
	value, negate = strings.CutPrefix(value, "!")
	code = upperASCII(strings.TrimSpace(value))
	if code == "" {
		return "", false, errEmptyValue
	}
	if strings.Contains(code, "@") {
		return "", false, errors.New("attributes on a geoip entry")
	}
	if err := checkName(code); err != nil {
		return "", false, err
	}
	return code, negate, nil
}

// checkName checks a geodata code or attribute, which holds no colon,
// spaces or control characters: a rule with them could not be written back
// as the same rule.
func checkName(s string) error {
	if strings.Contains(s, ":") || hasSpace(s) {
		return fmt.Errorf("invalid geodata code or attribute %q", s)
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

// splitAttrs splits code@attr@attr into the upper-case code and the sorted,
// lowercase attributes.
func splitAttrs(value string) (code string, attrs []string, err error) {
	parts := strings.Split(value, "@")
	code = upperASCII(strings.TrimSpace(parts[0]))
	if code == "" {
		return "", nil, errEmptyValue
	}
	if err := checkName(code); err != nil {
		return "", nil, err
	}
	for _, a := range parts[1:] {
		a = lowerASCII(strings.TrimSpace(a))
		if a == "" {
			// Not the whole entry, as dropping it would make the rule match
			// more than written.
			return "", nil, errors.New("an empty attribute after @")
		}
		if err := checkName(a); err != nil {
			return "", nil, err
		}
		if !slices.Contains(attrs, a) {
			attrs = append(attrs, a)
		}
	}
	slices.Sort(attrs)
	return code, attrs, nil
}

// domainValue normalizes the domain of a full:, domain: or *-prefixed rule:
// lowercase, without a trailing dot, with internationalized labels in their
// xn-- form, and nothing that cannot be part of a host name.
func domainValue(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errNotHost
	}
	// Checked as written, before the xn-- form hides what it encodes.
	host := foldHost(strings.TrimSpace(value))
	switch {
	case host == "":
		return "", errEmptyValue
	case strings.ContainsAny(host, "/?#@:%*[]") || hasSpace(host):
		return "", errNotHost
	case host[0] == '.' || host[len(host)-1] == '.' || strings.Contains(host, ".."):
		return "", errors.New("an empty label in a domain")
	case host[0] == ';':
		// No host starts so, and a rule written so is a comment.
		return "", errNotHost
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", errors.New("an IP address in a domain rule")
	}
	if ip, ok := legacyIPv4(host); ok {
		// Hosts in this form are matched as addresses, so no domain rule
		// would ever match it.
		return "", fmt.Errorf("an IPv4 address in a legacy form, which matches as %v; write that", ip)
	}
	// Names travel as ASCII, as geosite files hold them: an internationalized
	// name matches in its xn-- form, as normalHost gives it.
	ascii, ok := asciiHost(host)
	if !ok {
		return "", errNotHost
	}
	return ascii, nil
}

// keywordValue normalizes the text of a keyword: or dotless: rule, which is
// matched as given, lowercase.
func keywordValue(value string) (string, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	switch {
	case text == "":
		return "", errEmptyValue
	case hasSpace(text):
		return "", errors.New("spaces in a keyword")
	case !isASCII(text):
		return "", errNonASCII
	}
	return text, nil
}

// hasSpace reports whether s holds spaces or control characters, which no
// host name does.
func hasSpace(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// parseIPv4Wildcard parses an IPv4 address whose trailing octets are *, such
// as 10.* or 192.168.*.*. It reports whether s looked like one.
func parseIPv4Wildcard(s string) (netip.Prefix, bool, error) {
	if !strings.HasSuffix(s, "*") || strings.ContainsAny(s, ":/") || strings.HasPrefix(s, "*") {
		return netip.Prefix{}, false, nil
	}
	parts := strings.Split(s, ".")
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
		if len(part) > 1 && part[0] == '0' {
			// Leading zeros, which netip rejects in addresses, may mean octal.
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

// upperASCII and lowerASCII change the case of ASCII letters only, which
// geodata codes and attributes are made of, so that the change can be undone.
func upperASCII(s string) string { return mapASCII(s, 'a', 'z', 'A'-'a') }

func lowerASCII(s string) string { return mapASCII(s, 'A', 'Z', 'a'-'A') }

func mapASCII(s string, lo, hi byte, delta int) string {
	i := strings.IndexFunc(s, func(r rune) bool { return r >= rune(lo) && r <= rune(hi) })
	if i < 0 {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if b[i] >= lo && b[i] <= hi {
			b[i] = byte(int(b[i]) + delta)
		}
	}
	return string(b)
}
