package geomatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustPorts(t testing.TB, rules ...string) *Matcher {
	t.Helper()
	m, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPortSyntax(t *testing.T) {
	for in, want := range map[string]string{
		"example.com:443":                 "example.com:443",
		"10.0.0.0/8:22,3389":              "10.0.0.0/8:22,3389",
		"[2001:db8::/32]:1000-2000":       "[2001:db8::/32]:1000-2000",
		"10.0.0.1-10.0.0.50":              "10.0.0.1-10.0.0.50",
		"10.0.0.0-10.0.0.255":             "10.0.0.0/24",
		"10.0.0.7-10.0.0.7":               "10.0.0.7",
		"1.1.1.1 - 1.1.1.5":               "1.1.1.1-1.1.1.5",
		"2001:db8::1-2001:db8::9":         "2001:db8::1-2001:db8::9",
		"[2001:db8::1-2001:db8::9]:443":   "[2001:db8::1-2001:db8::9]:443",
		"::ffff:10.0.0.1-::ffff:10.0.0.9": "10.0.0.1-10.0.0.9",
		"10.0.0.1-10.0.0.50:22":           "10.0.0.1-10.0.0.50:22",
		"localhost:80,443":                "localhost:80,443",
		"host:443,80,81-90,85":            "host:80-90,443",
		"host: 80 , 443":                  "host:80,443",
		"host:0080":                       "host:80",
		"host:0-65535":                    "host",
		"host:0-100,101-65535":            "host",
		"domain:Example.com:443":          "domain:example.com:443",
		"full:a.b:1":                      "full:a.b:1",
		"keyword:ads:80":                  "keyword:ads:80",
		"dotless::22":                     "dotless::22",
		"dotless:intra:22":                "dotless:intra:22",
		"geoip:!CN:22":                    "geoip:!cn:22",
		"geosite:Google@CN:443":           "geosite:google@cn:443",
		"*.example.com:443":               "*.example.com:443",
		".example.com:443":                ".example.com:443",
		"*example.com:8080":               "domain:example.com:8080",
		"10.*:22":                         "10.0.0.0/8:22",
		"[10.0.0.1]:22":                   "10.0.0.1:22",
		"[2001:DB8::1]:443":               "[2001:db8::1]:443",
		"[fe80::1%25eth0]:80":             "[fe80::1]:80",
		"[::1]":                           "::1",
		"2001:db8::1":                     "2001:db8::1",
		"2001:db8::1:443":                 "2001:db8::1:443",
		"fe80::1%eth0":                    "fe80::1",
		"https://Example.com:8443/x":      "example.com:8443",
		"https://example.com/x":           "example.com",
		"//user@example.com:81/x":         "example.com:81",
		"http://[::1]:8080/":              "[::1]:8080",
		"regexp:^a:b$":                    "regexp:^a:b$",
		"ext:C:\\geo\\x.dat:!cn":          "ext:C:\\geo\\x.dat:!cn",
		"ext-ip:ip.dat:cn":                "ext-ip:ip.dat:cn",
		"example.com：443":                 "example.com:443",
		"my-host.example:22":              "my-host.example:22",
		"10.0.0.0/8":                      "10.0.0.0/8",
		"example.com":                     "example.com",
	} {
		r, err := ParseRule(in)
		if err != nil {
			t.Errorf("ParseRule(%q) error = %v", in, err)
			continue
		}
		if got := r.String(); got != want {
			t.Errorf("ParseRule(%q).String() = %q, want %q", in, got, want)
		}
		back, err := ParseRule(r.String())
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Errorf("round trip of %q = %+v, %v; want %+v", r.String(), back, err, r)
		}
	}
}

// TestPortRules checks rules of ports alone, which match every address on
// their ports.
func TestPortRules(t *testing.T) {
	for in, want := range map[string]string{
		"*:25": "*:25", "* : 8000-9000,80": "*:80,8000-9000", "*:0-65535": "*:0-65535",
	} {
		r, err := ParseRule(in)
		if err != nil || r.Kind != RulePort || r.String() != want || !r.IsIP() || !r.IsDomain() {
			t.Errorf("ParseRule(%q) = %+v, %v; want %s", in, r, err, want)
		}
	}
	for _, in := range []string{"*", "*:", "*:x", "[*]:1"} {
		if _, err := ParseRule(in); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v, want invalid", in, err)
		}
	}
	if _, err := (Compiler{Kinds: IPKinds}).ParseRule("*:25"); !errors.Is(err, ErrKindDisabled) {
		t.Errorf("a port rule among IPKinds: %v", err)
	}
	m := MustCompile([]string{"*:25", "domain:a.test"})
	ap := netip.MustParseAddrPort
	for addr, want := range map[string]bool{
		"mx.example:25": true, "10.0.0.1:25": true, "[::1]:25": true, "mx.example:26": false,
		"mx.example": false, "mx.example:smtp": true, "a.test": true,
	} {
		if m.Match(addr) != want {
			t.Errorf("Match(%q) != %v", addr, want)
		}
	}
	if r, ok := m.FindAddrPort(ap("10.0.0.1:25")); !ok || r.String() != "*:25" {
		t.Errorf("FindAddrPort = %v, %v", r, ok)
	}
	if !m.HasIPRules() || !m.HasDomainRules() || !m.HasPortRules() {
		t.Error("Has…Rules")
	}
	deny := Policy{Deny: MustCompile([]string{"*:25"})}
	if deny.AllowsAddrPort(ap("10.0.0.1:25")) || !deny.AllowsAddrPort(ap("10.0.0.1:587")) || !deny.Allows("mx.example") {
		t.Error("denylist of a port")
	}
	allow := Policy{Allow: MustCompile([]string{"*:80,443"})}
	if !allow.Allows("x.test:443") || allow.Allows("x.test:22") || !allow.AllowsIP(netip.MustParseAddr("10.0.0.1")) {
		t.Error("allowlist of ports")
	}
	if d := allow.Decide("x.test:22"); d.Allowed || d.Matched {
		t.Errorf("Decide = %v", d)
	}
	// A Rule value without ports means every port.
	all, err := CompileRules([]Rule{{Kind: RulePort}})
	if err != nil {
		t.Fatal(err)
	}
	if all.Rules()[0].String() != "*:0-65535" || !all.Match("a.b:1") {
		t.Errorf("CompileRules(port rule) = %v", all.Rules())
	}
}

func TestPortSyntaxErrors(t *testing.T) {
	for in, off := range map[string]int{
		"10.0.0.0/8:22,99999":           14,
		"example.com:80,":               15,
		"example.com:":                  12,
		"example.com:9-1":               12,
		"example.com:1-x":               14,
		"keyword:a:b":                   10,
		"10.0.0.5-10.0.0.1":             0,
		"10.0.0.1-10.0.0.300":           9,
		"10.0.0.1-2001:db8::1":          0,
		"2001:db8::/32:22":              13,
		"2001:db8::1-2001:db8::9:80000": 23,
		"[2001:db8::1":                  0,
		"[2001:db8::1]x":                13,
		"[example.com]:443":             1,
		"[10.0.0.0/33]":                 1,
		"example.com：x":                 14,
		"https://a.com:x/":              14,
		"  geoip:cn:22,,":               12,
		"domain:a.com:1,2,3,0x":         20,
	} {
		_, err := ParseRule(in)
		var se *SyntaxError
		var re *RuleError
		if !errors.As(err, &se) || !errors.As(err, &re) || !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v, want a *SyntaxError", in, err)
			continue
		}
		if se.Offset != off || re.Rule != strings.TrimSpace(in) {
			t.Errorf("ParseRule(%q) = %v at %d, want offset %d", in, err, se.Offset, off)
		}
	}
	for _, in := range []string{"ful:example.com", "localhost:https", "full:a b:1"} {
		if _, err := ParseRule(in); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v, want invalid", in, err)
		}
	}
}

func TestPortMatch(t *testing.T) {
	m := mustPorts(t, "example.com:443", "10.0.0.0/8:22,3389", "[2001:db8::/32]:1000-2000",
		"10.1.0.1-10.1.0.50", "domain:any.test", "geoip:private:53")
	ap := netip.MustParseAddrPort
	for addr, want := range map[string]bool{
		"example.com:443":          true,
		"example.com:0443":         true,
		"example.com:80":           false,
		"example.com":              false, // no port
		"https://example.com/":     true,  // the scheme's port
		"HTTPS://example.com:443/": true,
		"http://example.com/":      false,
		"wss://example.com/x":      true,
		"https://example.com:/":    true,
		"example.com:https":        true, // a port that cannot be read
		"example.com:99999":        true,
		"example.com:":             true,
		"10.2.3.4:22":              true,
		"10.2.3.4:23":              false,
		"10.2.3.4":                 false,
		"[2001:db8::5]:1500":       true,
		"[2001:db8::5]:999":        false,
		"[2001:db8::5]x":           true,
		"2001:db8::5":              false,
		"10.1.0.7":                 true,
		"10.1.0.50:1":              true,
		"10.1.0.51":                false,
		"any.test:1":               true,
		"192.168.1.1:53":           true,
		"192.168.1.1:54":           false,
	} {
		if got := m.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
		if _, ok := m.Find(addr); ok != m.Match(addr) {
			t.Errorf("Find(%q) = %v, Match disagrees", addr, ok)
		}
	}
	if !m.MatchAddrPort(ap("10.2.3.4:22")) || m.MatchAddrPort(ap("10.2.3.4:23")) || m.MatchIP(netip.MustParseAddr("10.2.3.4")) {
		t.Error("MatchAddrPort")
	}
	if r, ok := m.FindAddrPort(ap("[::ffff:10.2.3.4]:3389")); !ok || r.String() != "10.0.0.0/8:22,3389" {
		t.Errorf("FindAddrPort = %v, %v", r, ok)
	}
	if !m.MatchNetAddr(&net.TCPAddr{IP: net.ParseIP("10.2.3.4"), Port: 3389}) ||
		m.MatchNetAddr(&net.UDPAddr{IP: net.ParseIP("10.2.3.4"), Port: 3388}) ||
		m.MatchNetAddr(&net.IPAddr{IP: net.ParseIP("10.2.3.4")}) ||
		!m.MatchNetAddr(&net.TCPAddr{IP: net.ParseIP("10.2.3.4"), Port: 70000}) {
		t.Error("MatchNetAddr")
	}
	if !m.MatchDomain("example.com:443") || m.MatchDomain("example.com:80") ||
		!m.MatchHostIP("example.com:443", netip.Addr{}) || m.MatchHostIP("example.com", netip.MustParseAddr("10.2.3.4")) {
		t.Error("MatchDomain, MatchHostIP")
	}
	if !m.HasPortRules() || MustCompile([]string{"a.b"}).HasPortRules() || (*Matcher)(nil).HasPortRules() {
		t.Error("HasPortRules")
	}
	if m.Len() != 6 || !m.HasIPRules() || !m.HasDomainRules() {
		t.Errorf("Len = %d", m.Len())
	}
}

func TestPortPolicy(t *testing.T) {
	deny := Policy{Deny: mustPorts(t, "example.com:22", "10.0.0.0/8:22")}
	allow := Policy{Allow: mustPorts(t, "example.com:443", "10.0.0.0/8:443")}
	for _, tt := range []struct {
		p    Policy
		addr string
		want bool
		rule string
	}{
		{deny, "example.com", true, ""},
		{deny, "example.com:22", false, "example.com:22"},
		{deny, "example.com:80", true, ""},
		{deny, "example.com:ssh", false, "example.com:22"},
		{allow, "example.com", true, "example.com:443"},
		{allow, "example.com:443", true, "example.com:443"},
		{allow, "example.com:80", false, ""},
		{allow, "example.com:https", false, ""},
		{allow, "https://example.com", true, "example.com:443"},
		{allow, "other.com", false, ""},
	} {
		d := tt.p.Decide(tt.addr)
		if d.Allowed != tt.want || tt.p.Allows(tt.addr) != tt.want || d.Matched != (tt.rule != "") || d.Matched && d.Rule.String() != tt.rule {
			t.Errorf("%+v Decide(%q) = %v, want %v by %q", tt.p, tt.addr, d, tt.want, tt.rule)
		}
	}
	ap := netip.MustParseAddrPort
	ip := netip.MustParseAddr("10.1.1.1")
	if !deny.AllowsIP(ip) || deny.AllowsAddrPort(ap("10.1.1.1:22")) || !deny.AllowsAddrPort(ap("10.1.1.1:23")) {
		t.Error("denylist by address and port")
	}
	if !allow.AllowsIP(ip) || allow.AllowsAddrPort(ap("10.1.1.1:22")) || !allow.DecideAddrPort(ap("10.1.1.1:443")).Allowed {
		t.Error("allowlist by address and port")
	}
	// Both lists: the port decides what either list matches.
	both := Policy{Allow: mustPorts(t, "10.0.0.0/8"), Deny: mustPorts(t, "10.0.0.0/8:22")}
	if both.AllowsAddrPort(ap("10.1.1.1:22")) || !both.AllowsAddrPort(ap("10.1.1.1:80")) || !both.AllowsIP(ip) {
		t.Error("allowlist with denied ports")
	}
	exceptions := Policy{Allow: mustPorts(t, "10.0.0.0/8:443"), Deny: mustPorts(t, "10.0.0.0/8"), Priority: AllowFirst}
	if !exceptions.AllowsAddrPort(ap("10.1.1.1:443")) || exceptions.AllowsAddrPort(ap("10.1.1.1:80")) {
		t.Error("denylist with allowed ports")
	}
	levels := Levels{Policies: []Policy{deny, allow}}
	if levels.AllowsAddrPort(ap("10.1.1.1:22")) || !levels.AllowsIP(ip) || !levels.HasPortRules() ||
		levels.DecideAddrPort(ap("10.1.1.1:80")).Allowed {
		t.Error("Levels")
	}
	first := Levels{Policies: []Policy{allow, deny}, FirstMatch: true, DenyUnmatched: true}
	if d := first.DecideAddrPort(ap("10.1.1.1:443")); !d.Allowed || d.Level != 0 {
		t.Errorf("FirstMatch Decide = %v", d)
	}
	if d := first.DecideAddrPort(ap("10.1.1.1:22")); d.Allowed || d.Level != 1 {
		t.Errorf("FirstMatch Decide = %v", d)
	}
	if !deny.HasPortRules() || (Policy{}).HasPortRules() {
		t.Error("HasPortRules")
	}
}

func TestPortRouter(t *testing.T) {
	r := Router[string]{
		Routes: []Route[string]{
			{Matcher: mustPorts(t, "domain:example.com:22"), Target: "block"},
			{Matcher: mustPorts(t, "domain:example.com"), Target: "direct"},
		},
		Default: "proxy",
	}
	for addr, want := range map[string]string{
		"example.com:22": "block", "example.com:443": "direct", "example.com": "direct", "other.test:22": "proxy",
	} {
		if got := r.Route(addr); got != want || r.Find(addr).Target != want {
			t.Errorf("Route(%q) = %s, want %s", addr, got, want)
		}
	}
	ip := mustPorts(t, "10.0.0.0/8:22")
	ipr := Router[int]{Routes: []Route[int]{{Matcher: ip, Target: 1}}}
	if ipr.RouteAddrPort(netip.MustParseAddrPort("10.0.0.1:22")) != 1 || ipr.FindAddrPort(netip.MustParseAddrPort("10.0.0.1:23")).Matched {
		t.Error("RouteAddrPort")
	}
}

func TestPortRuleValues(t *testing.T) {
	m, err := CompileRules([]Rule{
		{Kind: RuleDomain, Value: "example.com", Ports: []PortRange{{443, 443}, {80, 80}, {81, 81}}},
		{Kind: RuleIP, Prefix: netip.MustParsePrefix("10.0.0.1/32"), Last: netip.MustParseAddr("10.0.0.20")},
		{Kind: RuleIP, Prefix: netip.MustParsePrefix("10.0.1.0/32"), Last: netip.MustParseAddr("10.0.1.255")},
		{Kind: RuleRegexp, Value: "^a", Ports: []PortRange{{1, 1}}},
		{Kind: RuleKeyword, Value: "x", Ports: []PortRange{{9, 1}}},
		{Kind: RuleIP, Prefix: netip.MustParsePrefix("10.0.0.0/8"), Last: netip.MustParseAddr("10.0.0.20")},
		{Kind: RuleIP, Prefix: netip.MustParsePrefix("10.0.0.9/32"), Last: netip.MustParseAddr("10.0.0.1")},
		{Kind: RuleGeoIP, File: "f.dat", Code: "CN", Ports: []PortRange{{1, 1}}},
	})
	var errs RuleErrors
	if !errors.As(err, &errs) || len(errs) != 5 || errs[0].Index != 3 || errs[4].Index != 7 {
		t.Fatalf("CompileRules error = %v", err)
	}
	if got := fmt.Sprint(m.Rules()); got != "[domain:example.com:80-81,443 10.0.0.1-10.0.0.20 10.0.1.0/24]" {
		t.Errorf("Rules = %s", got)
	}
	if !m.Match("10.0.0.20") || m.Match("10.0.0.21") || !m.Match("a.example.com:81") || m.Match("a.example.com:82") {
		t.Error("compiled rule values")
	}
	// Rules with ports and ranges write and read themselves as text.
	text, err := json.Marshal(append(m.Rules(), Rule{Kind: RulePort, Ports: []PortRange{{25, 25}}}))
	var back []Rule
	if err != nil || json.Unmarshal(text, &back) != nil || !reflect.DeepEqual(back, append(m.Rules(), Rule{Kind: RulePort, Ports: []PortRange{{25, 25}}})) {
		t.Errorf("JSON of rules = %s, %v; read back %v", text, err, back)
	}
	// Normalize writes the canonical form.
	out, err := Compiler{}.Normalize([]string{"host:443,80", "HOST:80,443", "10.0.0.0-10.0.0.255:1"})
	if err != nil || !reflect.DeepEqual(out, []string{"host:80,443", "10.0.0.0/24:1"}) {
		t.Errorf("Normalize = %q, %v", out, err)
	}
}

func TestQueryPort(t *testing.T) {
	for in, want := range map[string]int32{
		"example.com":          portNone,
		"example.com:443":      443,
		" example.com:443 ":    443,
		"example.com:0":        0,
		"example.com:65535":    65535,
		"example.com:65536":    portBad,
		"example.com:":         portBad,
		"example.com:x":        portBad,
		"[::1]:80":             80,
		"[::1]":                portNone,
		"[::1]x":               portBad,
		"::1":                  portNone,
		"http://a.com/":        80,
		"Http://a.com:/":       80,
		"https://a.com/x:1":    443,
		"ftp://u:p@a.com/":     21,
		"ws://a.com:81":        81,
		"gopher://a.com/":      portNone,
		"gopher://a.com:/":     portBad,
		"//a.com:82/x":         82,
		"a.com/x?y=b.com:1":    portNone,
		"a.com:83\\@b.com:84":  83,
		"user@a.com:85":        85,
		"a.com:86/x":           86,
		"https://a.com\\:1/":   443,
		"":                     portNone,
		"https://[::1]:87/":    87,
		"https://u@[::1]/":     443,
		"blocked.com?r=http:/": portNone,
	} {
		if got := queryPort(in); got != want {
			t.Errorf("queryPort(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestRangePrefixes(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 2000 {
		var a, b netip.Addr
		if rng.IntN(2) == 0 {
			a = netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(4)), byte(rng.IntN(256))})
			b = netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(4)), byte(rng.IntN(256))})
		} else {
			a = netip.AddrFrom16([16]byte{0x20, 1, 15: byte(rng.IntN(256)), 14: byte(rng.IntN(2))})
			b = netip.AddrFrom16([16]byte{0x20, 1, 15: byte(rng.IntN(256)), 14: byte(rng.IntN(2))})
		}
		if b.Less(a) {
			a, b = b, a
		}
		ps := rangePrefixes(a, b, nil)
		if len(ps) > 2*a.BitLen() {
			t.Fatalf("%v-%v: %d prefixes", a, b, len(ps))
		}
		// Contiguous, in order, from a to b.
		next := a
		for _, p := range ps {
			if p.Addr() != next || p != p.Masked() {
				t.Fatalf("%v-%v: %v", a, b, ps)
			}
			last := lastAddr(p)
			next = last.Next()
			if last == b && p != ps[len(ps)-1] {
				t.Fatalf("%v-%v: %v", a, b, ps)
			}
		}
		if lastAddr(ps[len(ps)-1]) != b {
			t.Fatalf("%v-%v: %v", a, b, ps)
		}
	}
	all := rangePrefixes(netip.IPv6Unspecified(), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), nil)
	if len(all) != 1 || all[0].Bits() != 0 {
		t.Errorf("whole IPv6 = %v", all)
	}
	all4 := rangePrefixes(netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), nil)
	if len(all4) != 1 || all4[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Errorf("whole IPv4 = %v", all4)
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// TestPortIndexAgrees compares the port index and the Find index with
// trying the rules in order, on random rules with ports, and the fallback
// of the port index with its intervals.
func TestPortIndexAgrees(t *testing.T) {
	saved := maxCover
	defer func() { maxCover = saved }()
	rng := rand.New(rand.NewPCG(5, 6))
	labels := []string{"a", "b", "ab", "x"}
	name := func() string {
		s := labels[rng.IntN(len(labels))]
		if rng.IntN(2) == 0 {
			s += "." + labels[rng.IntN(len(labels))]
		}
		return s
	}
	ports := func() string {
		var items []string
		for range 1 + rng.IntN(3) {
			p := rng.IntN(8)
			if rng.IntN(3) == 0 {
				items = append(items, fmt.Sprintf("%d-%d", p, p+rng.IntN(5)))
			} else {
				items = append(items, fmt.Sprint(p))
			}
		}
		return strings.Join(items, ",")
	}
	for round := range 400 {
		maxCover = []int{1 << 22, 0}[round%2]
		var rules []string
		for range 1 + rng.IntN(20) {
			var r string
			switch rng.IntN(6) {
			case 0:
				r = fmt.Sprintf("10.0.%d.0/%d", rng.IntN(2), 23+rng.IntN(3))
			case 1:
				r = fmt.Sprintf("10.0.0.%d-10.0.1.%d", rng.IntN(256), rng.IntN(256))
			case 2:
				r = "domain:" + name()
			case 3:
				r = "keyword:" + labels[rng.IntN(len(labels))]
			case 4:
				r = "regexp:^" + labels[rng.IntN(len(labels))]
			default:
				r = "full:" + name()
			}
			if rng.IntN(3) > 0 {
				if strings.HasPrefix(r, "regexp:") {
					r = "keyword:" + labels[rng.IntN(len(labels))]
				}
				r += ":" + ports()
			}
			rules = append(rules, r)
		}
		m, err := Compile(rules)
		if err != nil {
			t.Fatalf("Compile(%q): %v", rules, err)
		}
		m.once.Do(m.buildExplain)
		for range 60 {
			var tg target
			if rng.IntN(2) == 0 {
				tg = ipTarget(netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(2)), byte(rng.IntN(256))}))
			} else {
				tg = target{host: name()}
			}
			switch rng.IntN(4) {
			case 0:
				tg.port = 0 // none
			case 1:
				tg.port = -1 // cannot be read
			default:
				tg.port = int32(rng.IntN(14)) + 1
			}
			for _, allow := range []bool{false, true} {
				port := tg.portOf()
				want := -1
				for i := range m.probes {
					if m.probes[i].matchFor(tg, port, allow) {
						want = i
						break
					}
				}
				if got := m.explain.firstFor(m.probes, tg, port, allow); got != want || m.match(tg, allow) != (want >= 0) {
					t.Fatalf("round %d, rules %q, target %+v, allow %v: index finds %d, match %v, in order %d",
						round, rules, tg, allow, got, m.match(tg, allow), want)
				}
			}
		}
	}
}

func TestPortQueriesDoNotAllocate(t *testing.T) {
	m := mustPorts(t, "example.com:443", "10.0.0.0/8:22,3389", "keyword:ads:80", "domain:b.test:1-9", "full:x.test")
	p := Policy{Allow: m, Deny: mustPorts(t, "10.9.0.0/16:22")}
	ap := netip.MustParseAddrPort("10.1.2.3:3389")
	tcp := &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 22}
	for name, f := range map[string]func(){
		"Match":          func() { m.Match("www.example.com:443") },
		"Match URL":      func() { m.Match("https://example.com/x") },
		"MatchAddrPort":  func() { m.MatchAddrPort(ap) },
		"MatchNetAddr":   func() { m.MatchNetAddr(tcp) },
		"Find":           func() { m.Find("example.com:443") },
		"FindAddrPort":   func() { m.FindAddrPort(ap) },
		"Allows":         func() { p.Allows("b.test:5") },
		"Decide":         func() { p.Decide("ads.test:80") },
		"DecideAddrPort": func() { p.DecideAddrPort(ap) },
		"no port":        func() { p.Decide("example.com") },
	} {
		f()
		if n := testing.AllocsPerRun(100, f); n != 0 {
			t.Errorf("%s: %v allocations", name, n)
		}
	}
}

func FuzzPortRule(f *testing.F) {
	for _, s := range []string{"example.com:443", "10.0.0.0/8:22,3389", "[2001:db8::/32]:1000-2000", "10.0.0.1-10.0.0.50",
		"geosite:a@b:1", "geoip:!cn:2-3", "https://a.b:8/x", "[::1-::9]:0", "dotless::1", "2001:db8::/32:22"} {
		f.Add(s, "a.b:443")
	}
	f.Fuzz(func(t *testing.T, rule, addr string) {
		// Rules find ports where queries do.
		scheme, port, off := portText(rule)
		if _, want := hostPortOf(rule); portField(scheme, port) != want || off < 0 || off > len(rule) || port != "" && rule[off:off+len(port)] != port {
			t.Fatalf("portText(%q) = %q at %d, hostPortOf finds %d", rule, port, off, want)
		}
		r, err := ParseRule(rule)
		if err != nil {
			var se *SyntaxError
			var re *RuleError
			if errors.As(err, &se) && (!errors.As(err, &re) || se.Offset < 0 || se.Offset > len(re.Rule)) {
				t.Fatalf("ParseRule(%q) = %v: offset outside the rule", rule, err)
			}
			return
		}
		back, err := ParseRule(r.String())
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("round trip of %q: %+v -> %q -> %+v, %v", rule, r, r.String(), back, err)
		}
		m, err := CompileRules([]Rule{r, {Kind: RuleKeyword, Value: "zz", Ports: []PortRange{{1, 9}}}})
		if err != nil && !errors.Is(err, ErrGeoData) {
			t.Fatalf("CompileRules(%v) = %v", r, err)
		}
		if _, ok := m.Find(addr); ok != m.Match(addr) {
			t.Fatalf("rule %q: Find(%q) = %v, Match disagrees", rule, addr, ok)
		}
		for _, p := range []Policy{{Allow: m}, {Deny: m}} {
			if d := p.Decide(addr); d.Allowed != p.Allows(addr) {
				t.Fatalf("rule %q: Decide(%q) = %v, Allows disagrees", rule, addr, d)
			}
		}
	})
}
