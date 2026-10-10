package geomatch

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
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
)

// Rule is a parsed rule. ParseRule returns rules in a normal form: lowercase
// domains, codes with upper-case ASCII letters, sorted attributes and masked
// prefixes, so that String gives a rule one spelling however it was written.
type Rule struct {
	Kind RuleKind
	// Prefix is the address range of RuleIP.
	Prefix netip.Prefix
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
}

var (
	errNoRule     = errors.New("empty rule or comment")
	errEmptyValue = errors.New("empty value")
	errNotHost    = errors.New("not an IP address, CIDR or domain")
	errWildcard   = errors.New("a wildcard must be a leading * of a domain or trailing octets of an IPv4 address")
)

// IsComment reports whether s is empty or a comment, starting with # or ;,
// which Compile skips.
func IsComment(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s[0] == '#' || s[0] == ';'
}

// ParseRule parses one rule, in the syntax the package documentation lists,
// without reading any geodata. It fails for an empty rule or a comment.
func ParseRule(s string) (Rule, error) {
	r, err := parseRule(s)
	if err != nil {
		return Rule{}, err
	}
	return r, nil
}

func parseRule(s string) (Rule, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "：", ":"))
	if IsComment(s) {
		return Rule{}, errNoRule
	}
	kind, value, ok := strings.Cut(s, ":")
	if !ok {
		return parsePlain(s)
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
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
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
	return parsePlain(s)
}

// parsePlain parses a rule without a kind: an IP address, a CIDR, an IPv4
// wildcard, a *-prefixed domain or a plain domain, which matches as a keyword.
func parsePlain(s string) (Rule, error) {
	if p, ok, err := parseIPv4Wildcard(s); ok || err != nil {
		return Rule{Kind: RuleIP, Prefix: p}, err
	}
	if strings.Contains(s, "/") && !strings.Contains(s, "://") {
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
	host := HostOf(s)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap().WithZone("")
		return Rule{Kind: RuleIP, Prefix: netip.PrefixFrom(ip, ip.BitLen())}, nil
	}
	// A leading dot, as in ".example.com", is kept: the keyword then
	// matches subdomains and not the domain itself.
	dot := ""
	if rest, ok := strings.CutPrefix(host, "."); ok {
		dot, host = ".", rest
	}
	host, err := domainValue(host)
	return Rule{Kind: RuleKeyword, Value: dot + host}, err
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
func (r Rule) String() string {
	code := lowerASCII(r.Code)
	if r.Negate {
		code = "!" + code
	}
	for _, a := range r.Attrs {
		code += "@" + a
	}
	switch r.Kind {
	case RuleIP:
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
func (r Rule) IsIP() bool {
	return r.Kind == RuleIP || r.Kind == RuleGeoIP || r.Kind == RuleExt
}

// IsDomain reports whether the rule matches domain names.
func (r Rule) IsDomain() bool {
	return r.Kind >= RuleFull && r.Kind <= RuleExt
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
	return code, negate, nil
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
	for _, a := range parts[1:] {
		if a = lowerASCII(strings.TrimSpace(a)); a != "" && !slices.Contains(attrs, a) {
			attrs = append(attrs, a)
		}
	}
	slices.Sort(attrs)
	return code, attrs, nil
}

// domainValue normalizes the domain of a full:, domain: or *-prefixed rule:
// lowercase, without a trailing dot, and nothing that cannot be part of a
// host name.
func domainValue(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	switch {
	case host == "":
		return "", errEmptyValue
	case strings.ContainsAny(host, "/?#@:%*[]") || hasSpace(host):
		return "", errNotHost
	case host[0] == '.' || host[len(host)-1] == '.' || strings.Contains(host, ".."):
		return "", errors.New("an empty label in a domain")
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
	case hasSpace(text):
		return "", errors.New("spaces in a keyword")
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
