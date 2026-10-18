package geomatch

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestKindSet(t *testing.T) {
	var zero KindSet
	for k := RuleIP; k <= RuleExt; k++ {
		if !zero.Has(k) || !AllKinds.Has(k) {
			t.Errorf("%v not in every set", k)
		}
		if IPKinds.Has(k) != (k == RuleIP || k == RuleGeoIP) {
			t.Errorf("IPKinds.Has(%v)", k)
		}
		if DomainKinds.Has(k) != (k >= RuleFull && k <= RuleGeoSite) {
			t.Errorf("DomainKinds.Has(%v)", k)
		}
	}
	if zero.Has(0) || AllKinds.Has(RuleExt+1) {
		t.Error("Has of an unknown kind")
	}
	if s := KindsOf(RuleIP, RuleRegexp); !s.Has(RuleRegexp) || s.Has(RuleKeyword) {
		t.Error("KindsOf")
	}
	if s := AllKinds.Without(RuleRegexp, RuleExt); s.Has(RuleRegexp) || s.Has(RuleExt) || !s.Has(RuleKeyword) {
		t.Error("Without")
	}
	if zero.Without(RuleIP) != AllKinds&^KindsOf(RuleIP) || IPKinds.Without(RuleIP) != KindsOf(RuleGeoIP) {
		t.Error("Without of the zero KindSet or a subset")
	}
	if s := AllKinds &^ GeoKinds; s.Has(RuleGeoIP) || s.Has(RuleGeoSite) || s.Has(RuleExt) || !s.Has(RuleIP) || !s.Has(RuleDotless) {
		t.Error("GeoKinds")
	}
	if _, err := (Compiler{Kinds: AllKinds &^ GeoKinds}).ParseRule("geoip:private"); !errors.Is(err, ErrKindDisabled) {
		t.Errorf("geo rule without GeoKinds = %v", err)
	}
	if RuleSubdomain.String() != "subdomain" || RuleKind(99).String() != "kind 99" {
		t.Error("RuleKind.String")
	}
}

func TestCompilerKinds(t *testing.T) {
	c := Compiler{Kinds: AllKinds &^ KindsOf(RuleRegexp, RuleKeyword)}
	rules := []string{"regexp:^a", "ads", "domain:a.test", "10.0.0.0/8"}
	parsed, err := c.ParseRules(rules)
	if len(parsed) != 2 || !errors.Is(err, ErrKindDisabled) || !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("ParseRules = %v, %v", parsed, err)
	}
	m, err := c.Compile(rules)
	var errs RuleErrors
	if !errors.As(err, &errs) || len(errs) != 2 || errs[0].Index != 0 || errs[1].Index != 1 {
		t.Fatalf("Compile errors = %v", err)
	}
	if m.Len() != 2 || m.Match("ads.test") || !m.Match("a.test") {
		t.Errorf("Compile kept %v", m.Rules())
	}
	if _, err := (Compiler{Kinds: IPKinds}).ParseRule("full:a.test"); !errors.Is(err, ErrKindDisabled) {
		t.Errorf("ParseRule with IPKinds = %v", err)
	}
	if _, err := (Compiler{Kinds: IPKinds}).CompileRules([]Rule{{Kind: RuleKeyword, Value: "x"}}); !errors.Is(err, ErrKindDisabled) {
		t.Errorf("CompileRules with IPKinds = %v", err)
	}
}

func TestCompilerExtFiles(t *testing.T) {
	local := []string{"ext:geo.dat:cn", "ext-ip:sub/geoip.dat:cn", "ext-domain:./site.dat:cn"}
	outside := []string{"ext:/etc/geo.dat:cn", "ext:../geo.dat:cn", `ext:..\geo.dat:cn`, `ext:C:\geo.dat:cn`, "ext-ip:a/../../b.dat:cn"}
	for _, r := range append(local, outside...) {
		if _, err := (Compiler{ExtFiles: ExtAny}).ParseRule(r); err != nil {
			t.Errorf("ExtAny rejected %s: %v", r, err)
		}
		if _, err := (Compiler{ExtFiles: ExtNone}).ParseRule(r); !errors.Is(err, ErrExtDenied) {
			t.Errorf("ExtNone accepted %s: %v", r, err)
		}
		_, err := (Compiler{ExtFiles: ExtLocal}).ParseRule(r)
		if want := slices.Contains(outside, r); errors.Is(err, ErrExtDenied) != want {
			t.Errorf("ExtLocal %s = %v, want denied %v", r, err, want)
		}
	}
	for _, r := range []string{"geoip:cn", "geosite:cn"} {
		if _, err := (Compiler{ExtFiles: ExtNone}).ParseRule(r); err != nil {
			t.Errorf("ExtNone rejected %s: %v", r, err)
		}
	}
}

func TestCompilerLimits(t *testing.T) {
	c := Compiler{Limits: Limits{MaxRules: 3, MaxRuleLen: 12, MaxRegexps: 1}}
	rules := []string{"# a long comment is not a rule", "regexp:^a", "regexp:^b", "keyword:abcdefghij", "a.test", "b.test", "c.test"}
	parsed, err := c.ParseRules(rules)
	var errs RuleErrors
	if !errors.As(err, &errs) {
		t.Fatalf("ParseRules error = %v", err)
	}
	var idx []int
	for _, e := range errs {
		if !errors.Is(e, ErrLimit) || !errors.Is(e, ErrInvalidRule) {
			t.Errorf("error %v is not ErrLimit", e)
		}
		idx = append(idx, e.Index)
	}
	if !slices.Equal(idx, []int{2, 3, 6}) || len(parsed) != 3 {
		t.Errorf("limited rules %v, kept %v", idx, parsed)
	}
	// Each call counts afresh.
	if _, err := c.ParseRules(rules[4:6]); err != nil {
		t.Errorf("second call = %v", err)
	}
}

func TestErrorClasses(t *testing.T) {
	geo := testGeoData(t)
	_, err := Compiler{GeoData: geo}.Compile([]string{"full:", "geoip:nope", "geosite:cn", "ext:missing.dat:x", "foo*bar"})
	var errs RuleErrors
	if !errors.As(err, &errs) {
		t.Fatal(err)
	}
	invalid, data := errs.Filter(ErrInvalidRule), errs.Filter(ErrGeoData)
	if len(invalid) != 2 || invalid[0].Index != 0 || invalid[1].Index != 4 {
		t.Errorf("invalid = %v", invalid)
	}
	if len(data) != 2 || data[0].Index != 1 || data[1].Index != 3 || !errors.Is(data[0], ErrCodeNotFound) {
		t.Errorf("geodata = %v", data)
	}
	if !errors.Is(ErrNoGeoData, ErrGeoData) || errors.Is(ErrNoGeoData, ErrInvalidRule) || !errors.Is(errProto, ErrGeoData) {
		t.Error("error classes")
	}
	if _, err := ParseRule(" "); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("ParseRule(empty) = %v", err)
	}
}

func TestMatchHostIP(t *testing.T) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com"})
	cases := []struct {
		host string
		ip   string
		want string
	}{
		{"www.example.com", "192.0.2.1", "domain:example.com"},
		{"other.test", "10.1.1.1", "10.0.0.0/8"},
		{"www.example.com", "10.1.1.1", "10.0.0.0/8"}, // in rule order
		{"other.test", "192.0.2.1", ""},
		{"", "10.1.1.1", "10.0.0.0/8"},
		{"10.1.1.1", "", ""}, // the host is never read as an address
		{"example.com", "", "domain:example.com"},
	}
	for _, c := range cases {
		var ip netip.Addr
		if c.ip != "" {
			ip = netip.MustParseAddr(c.ip)
		}
		r, ok := m.FindHostIP(c.host, ip)
		if ok != (c.want != "") || ok && r.String() != c.want || m.MatchHostIP(c.host, ip) != ok {
			t.Errorf("FindHostIP(%q, %v) = %v, %v; want %q", c.host, ip, r, ok, c.want)
		}
	}
	allow := Policy{Allow: MustCompile([]string{"10.0.0.0/8"})}
	if !allow.AllowsHostIP("internal.test", netip.MustParseAddr("10.0.0.1")) || allow.AllowsDomain("internal.test") {
		t.Error("AllowsHostIP")
	}
	if d := allow.DecideHostIP("internal.test", netip.MustParseAddr("10.0.0.1")); !d.Allowed || d.Rule.String() != "10.0.0.0/8" {
		t.Errorf("DecideHostIP = %+v", d)
	}
}

func TestLevelsEveryLevel(t *testing.T) {
	global := Policy{Deny: MustCompile([]string{"192.0.2.0/24"})}
	user := Policy{Allow: MustCompile([]string{"10.0.0.0/8", "192.0.2.0/24"})}
	res := Policy{Deny: MustCompile([]string{"10.9.0.0/16"})}
	ps := Levels{Policies: []Policy{global, user, res}}
	for addr, want := range map[string]Decision{
		"10.1.1.1":  {Allowed: true, Matched: true, Level: 1},
		"192.0.2.1": {Allowed: false, Matched: true, Level: 0},
		"10.9.0.1":  {Allowed: false, Matched: true, Level: 2},
		"8.8.8.8":   {Allowed: false, Matched: false, Level: 1},
	} {
		d := ps.Decide(addr)
		if d.Allowed != want.Allowed || d.Matched != want.Matched || d.Level != want.Level {
			t.Errorf("Decide(%s) = %+v, want %+v", addr, d, want)
		}
		ip := netip.MustParseAddr(addr)
		tcp := &net.TCPAddr{IP: ip.AsSlice()}
		if ps.Allows(addr) != want.Allowed || ps.AllowsIP(ip) != want.Allowed || ps.AllowsNetAddr(tcp) != want.Allowed ||
			ps.AllowsHostIP("", ip) != want.Allowed || ps.DecideIP(ip).Level != d.Level || ps.DecideNetAddr(tcp).Level != d.Level ||
			ps.DecideHostIP("", ip).Level != d.Level {
			t.Errorf("forms disagree for %s", addr)
		}
	}
	if !(Levels{}).Allows("x") || !(Levels{}).Decide("x").Allowed || (Levels{}).Decide("x").Level != -1 {
		t.Error("empty Levels")
	}
	if ps.AllowsDomain("example.com") || ps.DecideDomain("example.com").Level != 1 {
		t.Error("domain against an IP allowlist")
	}
}

func TestStaleAndSources(t *testing.T) {
	geo := testGeoData(t)
	missing := filepath.Join(filepath.Dir(geo.IPFile), "later.dat")
	m := compileSkipping(t, Compiler{GeoData: geo}, []string{"geoip:cn", "geosite:cn", "geoip:us", "ext:later.dat:x", "10.0.0.0/8"}, 3)
	src := m.Sources()
	if len(src) != 3 || src[0].File != geo.IPFile || src[1].File != geo.SiteFile || src[2].File != missing ||
		src[0].Missing || src[0].Size == 0 || !src[2].Missing {
		t.Fatalf("Sources() = %+v", src)
	}
	if m.Stale() {
		t.Fatal("fresh Matcher is stale")
	}
	if err := os.WriteFile(missing, encodeDat(datEntry{code: "X", cidrs: []string{"1.0.0.0/8"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if !m.Stale() {
		t.Error("a file that appeared does not make it stale")
	}
	m = mustCompile(geo, []string{"geosite:cn"})
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(geo.SiteFile, later, later); err != nil {
		t.Fatal(err)
	}
	if !m.Stale() {
		t.Error("a changed file does not make it stale")
	}
	if MustCompile([]string{"geoip:private"}).Stale() || (*Matcher)(nil).Stale() || (*Matcher)(nil).Sources() != nil {
		t.Error("Matchers without files")
	}
}

// compileSkipping compiles rules that it expects to skip only the rule at
// index skip, and returns the Matcher of the others.
func compileSkipping(t *testing.T, c Compiler, rules []string, skip int) *Matcher {
	t.Helper()
	m, err := c.Compile(rules)
	var errs RuleErrors
	if !errors.As(err, &errs) || len(errs) != 1 || errs[0].Index != skip {
		t.Fatalf("Compile errors = %v, want rule %d skipped", err, skip)
	}
	return m
}

func TestExtAccessUnknown(t *testing.T) {
	if _, err := (Compiler{ExtFiles: ExtNone + 1}).ParseRule("ext:a.dat:x"); !errors.Is(err, ErrExtDenied) {
		t.Errorf("unknown ExtAccess = %v", err)
	}
	if _, err := (Compiler{ExtFiles: ExtNone + 1}).ParseRule("geoip:cn"); err != nil {
		t.Errorf("unknown ExtAccess on a default file = %v", err)
	}
}
