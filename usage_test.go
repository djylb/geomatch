package geomatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestUnknownKind(t *testing.T) {
	for _, s := range []string{"ful:example.com", "domian:example.com", "ip:1.2.3.4", "GeoIP2:cn", "a_b:c", "example:"} {
		_, err := ParseRule(s)
		var re *RuleError
		if !errors.Is(err, ErrInvalidRule) || !errors.As(err, &re) || re.Index != 0 {
			t.Errorf("ParseRule(%q) = %v, want an unknown kind", s, err)
		}
	}
	for s, want := range map[string]string{
		"localhost:8080":       "keyword:localhost",
		"example.com:443":      "keyword:example.com",
		"https://Example.com/": "keyword:example.com",
		"//example.com/x":      "keyword:example.com",
		"2001:db8::1":          "2001:db8::1",
		"fe80::1%eth0":         "fe80::1",
		"[::1]:80":             "::1",
	} {
		if r, err := ParseRule(s); err != nil || r.String() != want {
			t.Errorf("ParseRule(%q) = %v, %v; want %s", s, r, err, want)
		}
	}
}

func TestIPRangeRejected(t *testing.T) {
	for _, s := range []string{"1.1.1.1-1.1.1.5", "1.1.1.1 - 1.1.1.5", "2001:db8::1-2001:db8::9"} {
		if _, err := ParseRule(s); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v", s, err)
		}
	}
	if r, err := ParseRule("my-host.example"); err != nil || r.String() != "keyword:my-host.example" {
		t.Errorf("hyphenated host = %v, %v", r, err)
	}
}

func TestPlainDomain(t *testing.T) {
	for kind, want := range map[RuleKind][]string{
		0:           {"keyword:example.com", "keyword:.example.com"},
		RuleKeyword: {"keyword:example.com", "keyword:.example.com"},
		RuleDomain:  {"domain:example.com", "*.example.com"},
		RuleFull:    {"full:example.com", "*.example.com"},
	} {
		c := Compiler{PlainDomain: kind}
		for i, s := range []string{"Example.com:443", ".example.com"} {
			if r, err := c.ParseRule(s); err != nil || r.String() != want[i] {
				t.Errorf("PlainDomain %v: ParseRule(%q) = %v, %v; want %s", kind, s, r, err, want[i])
			}
		}
		// Only domains change: addresses and kinds written out do not.
		if r, _ := c.ParseRule("10.0.0.1"); r.Kind != RuleIP {
			t.Errorf("PlainDomain %v changed an address: %v", kind, r)
		}
		if r, _ := c.ParseRule("keyword:x"); r.Kind != RuleKeyword {
			t.Errorf("PlainDomain %v changed keyword:x: %v", kind, r)
		}
	}
	m := (Compiler{PlainDomain: RuleDomain}).compileOrFail(t, "example.com")
	if !m.Match("www.example.com") || !m.Match("example.com") || m.Match("notexample.com") {
		t.Error("PlainDomain RuleDomain matching")
	}
	if _, err := (Compiler{PlainDomain: RuleIP}).ParseRule("x.test"); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("PlainDomain RuleIP = %v", err)
	}
}

func (c Compiler) compileOrFail(t *testing.T, rules ...string) *Matcher {
	t.Helper()
	m, err := c.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestKindError(t *testing.T) {
	_, err := (Compiler{Kinds: IPKinds}).ParseRule("example.com")
	var ke *KindError
	if !errors.As(err, &ke) || ke.Kind != RuleKeyword || ke.Allowed != IPKinds ||
		!errors.Is(err, ErrKindDisabled) || !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("error = %v", err)
	}
	if got := ke.Error(); got != "keyword rules are not allowed here (allowed: ip, geoip)" {
		t.Errorf("message = %q", got)
	}
	if KindSet(0).String() != AllKinds.String() || KindSet(1).String() != "none" {
		t.Error("KindSet.String")
	}
}

func TestPriorityJSONNumber(t *testing.T) {
	var cfg struct{ Priority Priority }
	for in, want := range map[string]Priority{`0`: DenyFirst, `1`: AllowFirst, `"1"`: AllowFirst, `"allow-first"`: AllowFirst} {
		cfg.Priority = 9
		if err := json.Unmarshal([]byte(`{"Priority":`+in+`}`), &cfg); err != nil || cfg.Priority != want {
			t.Errorf("Unmarshal(%s) = %v, %v", in, cfg.Priority, err)
		}
	}
	cfg.Priority = AllowFirst
	if err := json.Unmarshal([]byte(`{"Priority":null}`), &cfg); err != nil || cfg.Priority != AllowFirst {
		t.Errorf("null = %v, %v", cfg.Priority, err)
	}
	for _, in := range []string{`2`, `true`, `"x"`} {
		if err := json.Unmarshal([]byte(`{"Priority":`+in+`}`), &cfg); err == nil {
			t.Errorf("Unmarshal(%s) accepted", in)
		}
	}
}

func TestNormalize(t *testing.T) {
	got, err := (Compiler{}).Normalize(SplitLines("*Example.COM\n# c\ndomain:example.com\n10.1.2.3/8\n\nfull:\n10.0.0.0/8\nfoo"))
	if want := []string{"domain:example.com", "10.0.0.0/8", "keyword:foo"}; !slices.Equal(got, want) {
		t.Errorf("Normalize = %q, want %q", got, want)
	}
	var errs RuleErrors
	if !errors.As(err, &errs) || len(errs) != 1 || errs[0].Index != 5 {
		t.Errorf("Normalize error = %v", err)
	}
	if got, err := (Compiler{}).Normalize(nil); len(got) != 0 || err != nil {
		t.Errorf("Normalize(nil) = %q, %v", got, err)
	}
}

func TestSetFiles(t *testing.T) {
	geo := testGeoData(t)
	first := geo.Files()
	m := mustCompile(geo, []string{"geoip:cn"})
	gen := geo.Generation()

	dir := t.TempDir()
	other := writeDat(t, dir, "geoip.dat", datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}})
	geo.SetFiles(GeoFiles{IP: " " + other + " "})
	if geo.Files().IP != other || geo.Generation() <= gen {
		t.Fatalf("Files() = %+v, generation %d", geo.Files(), geo.Generation())
	}
	if !m.Stale() || !m.Match("1.2.3.4") {
		t.Error("a Matcher of the old files is not stale, or changed")
	}
	if n := mustCompile(geo, []string{"geoip:cn"}); !n.Match("7.7.7.7") || n.Match("1.2.3.4") || n.Stale() {
		t.Error("new files not in use")
	}
	l, _ := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn"})
	geo.SetFiles(first)
	if replaced, err := l.Refresh(); !replaced || err != nil || !l.Matcher().Match("1.2.3.4") {
		t.Errorf("Live after SetFiles = %v, %v", replaced, err)
	}
	if (*GeoData)(nil).Files() != (GeoFiles{}) {
		t.Error("nil GeoData Files")
	}
}

func TestGenerationAndCheck(t *testing.T) {
	geo := testGeoData(t)
	missing := filepath.Join(filepath.Dir(geo.Files().IP), "later.dat")
	_, _ = Compiler{GeoData: geo}.Compile([]string{"geoip:cn", "geosite:cn", "ext:later.dat:x"})
	gen := geo.Check()
	if geo.Check() != gen {
		t.Fatal("Check without changes grew the generation")
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(geo.Files().Site, later, later); err != nil {
		t.Fatal(err)
	}
	if g := geo.Check(); g != gen+1 || geo.Check() != g {
		t.Fatalf("Check after a change = %d, want %d once", g, gen+1)
	}
	gen = geo.Generation()
	if err := os.WriteFile(missing, encodeDat(datEntry{code: "X", cidrs: []string{"1.0.0.0/8"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if geo.Check() != gen+1 {
		t.Error("a file that appeared did not grow the generation")
	}
	// A changed file indexed again when compiling grows it too.
	gen = geo.Generation()
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	mustCompile(geo, []string{"geoip:cn"})
	if geo.Generation() != gen+1 {
		t.Errorf("generation %d after a reindex, want %d", geo.Generation(), gen+1)
	}
}

func TestExtDirByKind(t *testing.T) {
	ipDir, siteDir := t.TempDir(), t.TempDir()
	ip := writeDat(t, ipDir, "geoip.dat", datEntry{code: "CN", cidrs: []string{"1.2.3.0/24"}})
	site := writeDat(t, siteDir, "geosite.dat", datEntry{code: "CN", domains: []Domain{{Type: DomainRoot, Value: "qq.com"}}})
	writeDat(t, ipDir, "extra-ip.dat", datEntry{code: "X", cidrs: []string{"5.0.0.0/8"}})
	writeDat(t, siteDir, "extra-site.dat", datEntry{code: "X", domains: []Domain{{Type: DomainFull, Value: "x.test"}}})
	geo := NewGeoData(GeoFiles{IP: ip, Site: site})
	m, err := Compiler{GeoData: geo}.Compile([]string{"ext-ip:extra-ip.dat:x", "ext-domain:extra-site.dat:x", "ext:extra-site.dat:x"})
	if err != nil || !m.Match("5.1.1.1") || !m.Match("x.test") {
		t.Fatalf("ext files by kind = %v", err)
	}
	only := NewGeoData(GeoFiles{Site: site})
	if _, err := (Compiler{GeoData: only}).Compile([]string{"ext-ip:extra-site.dat:x"}); !errors.Is(err, ErrGeoData) {
		t.Errorf("ext-ip: next to the site file = %v, want it found there and of the wrong kind", err)
	}
}

func TestMissingBounded(t *testing.T) {
	geo := NewGeoData(GeoFiles{Dir: t.TempDir()})
	rules := make([]string, 0, maxMissing+10)
	for i := range maxMissing + 10 {
		rules = append(rules, "ext:missing"+strconv.Itoa(i)+".dat:x")
	}
	_, _ = Compiler{GeoData: geo}.Compile(rules)
	geo.mu.Lock()
	n := len(geo.missing)
	geo.mu.Unlock()
	if n != maxMissing {
		t.Errorf("%d missing files tracked, want %d", n, maxMissing)
	}
	var nilGeo *GeoData
	if nilGeo.Generation() != 0 || nilGeo.Check() != 0 {
		t.Error("nil GeoData")
	}
}
