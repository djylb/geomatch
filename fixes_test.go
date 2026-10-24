package geomatch

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
)

// TestLegacyIPv4 checks that hosts in the legacy forms of IPv4, which system
// resolvers read as addresses, are matched as those addresses.
func TestLegacyIPv4(t *testing.T) {
	p := Policy{Deny: MustCompile([]string{"127.0.0.0/8", "geoip:private"})}
	for _, addr := range []string{"127.1:80", "2130706433:80", "0x7f.1:80", "0177.0.0.1", "0x7F000001", "127.0.1", "0:80", "http://127.1/"} {
		if p.Allows(addr) {
			t.Errorf("Allows(%q) passed the denylist", addr)
		}
	}
	for host, want := range map[string]string{"127.1": "127.0.0.1", "2130706433": "127.0.0.1", "0x7f.0.0.1": "127.0.0.1", "10.1": "10.0.0.1", "192.168.257": "192.168.1.1", "0x": "0.0.0.0"} {
		if ip, ok := legacyIPv4(host); !ok || ip != netip.MustParseAddr(want) {
			t.Errorf("legacyIPv4(%q) = %v, %v; want %s", host, ip, ok, want)
		}
	}
	for _, host := range []string{"1.2.3.4.5", "08", "0x1g", "256.1.1.1", "1.2.3.256", "4294967296", "a.1", "1..2", "", "example.com", "10.example"} {
		if ip, ok := legacyIPv4(host); ok {
			t.Errorf("legacyIPv4(%q) = %v", host, ip)
		}
	}
	// A domain query never reads an address, also in a legacy form.
	if (Policy{Allow: MustCompile([]string{"keyword:127"})}).AllowsDomain("127.1") {
		t.Error("AllowsDomain read 127.1 as a domain")
	}
	// A number is an address, which domain rules do not match.
	if MustCompile([]string{"dotless:"}).Match("10") {
		t.Error("dotless: matched the address 10")
	}
}

// TestEmptyAllowlistFailsClosed checks that an allowlist whose rules were
// all filtered out allows nothing.
func TestEmptyAllowlistFailsClosed(t *testing.T) {
	c := Compiler{Kinds: IPKinds}
	rules, err := c.ParseRules([]string{"regexp:x"})
	if err == nil || len(rules) != 0 {
		t.Fatalf("ParseRules = %v, %v", rules, err)
	}
	m, _ := c.CompileRules(rules)
	if (Policy{Allow: m}).Allows("x.com") || (Policy{Allow: m}).Allows("1.2.3.4") {
		t.Fatal("an allowlist of no rules allowed")
	}
	if !(Policy{Deny: m}).Allows("x.com") {
		t.Fatal("a denylist of no rules denied")
	}
}

// TestPlainRulesFromJSON checks that domains without a kind, decoded from
// configuration, take the PlainDomain of the Compiler that compiles them.
func TestPlainRulesFromJSON(t *testing.T) {
	var rules []Rule
	if err := json.Unmarshal([]byte(`["ok.com", ".sub.test", "keyword:kw"]`), &rules); err != nil {
		t.Fatal(err)
	}
	m, err := Compiler{PlainDomain: RuleDomain}.CompileRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{"ok.com": true, "www.ok.com": true, "ok.com.evil.net": false, "notok.com": false, "a.sub.test": true, "sub.test": false, "akwb": true} {
		if got := m.MatchDomain(host); got != want {
			t.Errorf("MatchDomain(%q) = %v, want %v", host, got, want)
		}
	}
	// By default, as rule lists mean it, a plain domain is a keyword.
	if !MustCompile([]string{"ok.com"}).Match("ok.com.evil.net") {
		t.Error("default plain domain is not a keyword")
	}
	if b, _ := json.Marshal(rules); string(b) != `["ok.com",".sub.test","keyword:kw"]` {
		t.Errorf("Marshal = %s", b)
	}
}

// TestInternationalizedNames checks that names are matched in their ASCII
// form.
func TestInternationalizedNames(t *testing.T) {
	m := MustCompile([]string{"domain:例子.cn", "full:Bücher.DE"})
	for _, host := range []string{"xn--fsqu00a.cn", "www.xn--fsqu00a.cn", "例子.cn", "xn--bcher-kva.de", "https://Bücher.de/"} {
		if !m.Match(host) {
			t.Errorf("Match(%q) = false", host)
		}
	}
	if got := HostOf("https://Bücher.de:443/x"); got != "xn--bcher-kva.de" {
		t.Errorf("HostOf = %q", got)
	}
	if _, err := ParseRule("full:\xff.com"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

// TestEmptyAttribute checks that a geosite rule with an empty attribute is
// invalid rather than the whole entry.
func TestEmptyAttribute(t *testing.T) {
	for _, s := range []string{"geosite:cn@", "geosite:cn@@ads", "ext:f.dat:cn@", "ext-domain:f.dat:cn@ads@"} {
		if _, err := ParseRule(s); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v", s, err)
		}
	}
}

// TestHostOfBackslash checks that a backslash ends the host, as browsers
// read it.
func TestHostOfBackslash(t *testing.T) {
	for in, want := range map[string]string{
		`http://evil.com\@good.com/`: "evil.com",
		`evil.com\good.com`:          "evil.com",
		`https://a.test\path`:        "a.test",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
	if (Policy{Allow: MustCompile([]string{"domain:good.com"})}).Allows(`http://evil.com\@good.com/`) {
		t.Error("allowlist passed by a backslash")
	}
}

// TestIPSet checks a set that changes while a Policy uses it.
func TestIPSet(t *testing.T) {
	var set IPSet
	p := Policy{Allow: &set}.WithName("registered")
	if p.Allows("192.0.2.1") {
		t.Fatal("empty set allowed")
	}
	set.Add(netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("::ffff:198.51.100.0/120"), netip.Prefix{})
	if !p.Allows("192.0.2.1") || !p.Allows("198.51.100.9") || p.Allows("192.0.2.2") {
		t.Fatal("set not followed")
	}
	if d := p.Decide("198.51.100.9"); d.Rule.String() != "198.51.100.0/24" || d.Name != "registered" {
		t.Fatalf("Decide = %+v", d)
	}
	if got := set.Prefixes(); len(got) != 2 || set.Len() != 2 {
		t.Fatalf("Prefixes = %v", got)
	}
	m := set.Matcher()
	if set.Matcher() != m {
		t.Fatal("unchanged set built again")
	}
	set.Remove(netip.MustParsePrefix("192.0.2.1/32"))
	if p.Allows("192.0.2.1") || set.Matcher() == m {
		t.Fatal("removal not followed")
	}
	var nilSet *IPSet
	if nilSet.Matcher() != nil {
		t.Fatal("nil IPSet")
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				a := netip.AddrFrom4([4]byte{10, byte(i), byte(j), 1})
				set.Add(netip.PrefixFrom(a, 32))
				if !p.AllowsIP(a) {
					t.Errorf("%v not allowed after Add", a)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestRefreshLivesReport checks the tags, errors and RefreshErr of Lives
// that a broken file breaks.
func TestRefreshLivesReport(t *testing.T) {
	geo := testGeoData(t)
	var lives []*Live
	for i := range 5 {
		l, err := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetTag(i)
		lives = append(lives, l)
	}
	replaceFile(t, geo.Files().IP, []byte{0x0a, 0xff})
	r := geo.RefreshLives()
	if len(r.Failed) != 5 || len(r.Errors) != 1 || len(r.Replaced) != 0 || !r.Changed() {
		t.Fatalf("RefreshLives = %+v; want 5 failed, one error", r)
	}
	tags := make([]int, 0, len(r.Failed))
	for _, l := range r.Failed {
		tags = append(tags, l.Tag().(int))
		if l.RefreshErr() == nil || l.Err() != nil || !l.Matcher().Match("1.2.3.4") {
			t.Fatalf("Live %v: RefreshErr %v, Err %v", l.Tag(), l.RefreshErr(), l.Err())
		}
	}
	slices.Sort(tags)
	if !slices.Equal(tags, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("tags %v", tags)
	}
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	if r := geo.RefreshLives(); len(r.Replaced) != 5 || lives[0].RefreshErr() != nil {
		t.Fatalf("after the fix: %+v, RefreshErr %v", r, lives[0].RefreshErr())
	}
}

// TestSiteAttrs checks the attributes of a geosite entry.
func TestSiteAttrs(t *testing.T) {
	geo := testGeoData(t)
	if attrs, err := geo.SiteAttrs("", "cn"); err != nil || !slices.Equal(attrs, []string{"api", "cn"}) {
		t.Fatalf("SiteAttrs = %v, %v", attrs, err)
	}
	if attrs, err := geo.SiteAttrs("geosite.dat", "google"); err != nil || len(attrs) != 0 {
		t.Fatalf("SiteAttrs of google = %v, %v", attrs, err)
	}
}

// TestDeadRulesRejected checks that rules no host could ever match are
// invalid rather than silently dead.
func TestDeadRulesRejected(t *testing.T) {
	for _, s := range []string{"keyword:例子", "regexp:例子", "dotless:本地", "full:127.1", "domain:2130706433", "*.0x7f.1", "127.1", "0x7f.0.0.1"} {
		if r, err := ParseRule(s); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v, %v; want invalid", s, r, err)
		}
	}
	// Keywords of digits still are keywords.
	if r, err := ParseRule("keyword:127.1"); err != nil || r.Value != "127.1" {
		t.Errorf("keyword:127.1 = %v, %v", r, err)
	}
}

// TestFullWidthDots checks that the full stops that IDNA reads as dots are
// dots in hosts and rules.
func TestFullWidthDots(t *testing.T) {
	if got := HostOf("https://www.baidu。com:443/"); got != "www.baidu.com" {
		t.Errorf("HostOf = %q", got)
	}
	m := MustCompile([]string{"domain:baidu．com"})
	if !m.Match("www.baidu。com") || !m.Match("baidu.com") {
		t.Error("full-width dots not read as dots")
	}
	if got := HostOf("\xffa.COM"); got != "" {
		t.Errorf("HostOf of invalid UTF-8 = %q", got)
	}
}
