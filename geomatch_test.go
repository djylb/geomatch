package geomatch

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// datEntry is one entry of a test geodata file: CIDRs for geoip, domains for
// geosite.
type datEntry struct {
	code    string
	cidrs   []string
	inverse bool
	domains []Domain
}

// writeDat writes entries as a GeoIPList or GeoSiteList file into dir and
// returns its path.
func writeDat(t testing.TB, dir, name string, entries ...datEntry) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, encodeDat(entries...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodeDat(entries ...datEntry) []byte {
	var out []byte
	for _, e := range entries {
		rec := appendBytesField(nil, 1, []byte(e.code))
		for _, c := range e.cidrs {
			p := netip.MustParsePrefix(c)
			cidr := appendBytesField(nil, 1, p.Addr().AsSlice())
			cidr = appendVarintField(cidr, 2, uint64(p.Bits()))
			rec = appendBytesField(rec, 2, cidr)
		}
		if e.inverse {
			rec = appendVarintField(rec, 3, 1)
		}
		for _, d := range e.domains {
			var dom []byte
			if d.Type != DomainKeyword {
				dom = appendVarintField(dom, 1, uint64(d.Type))
			}
			dom = appendBytesField(dom, 2, []byte(d.Value))
			for _, a := range d.Attrs {
				dom = appendBytesField(dom, 3, appendBytesField(nil, 1, []byte(a)))
			}
			rec = appendBytesField(rec, 2, dom)
		}
		out = appendBytesField(out, 1, rec)
	}
	return out
}

func testGeoData(t testing.TB) *GeoData {
	t.Helper()
	dir := t.TempDir()
	ip := writeDat(t, dir, "geoip.dat",
		datEntry{code: "CN", cidrs: []string{"1.2.3.0/24", "2001:db8::/32", "::ffff:5.6.7.0/120"}},
		datEntry{code: "US", cidrs: []string{"8.8.8.0/24"}},
		datEntry{code: "ODD", cidrs: []string{"9.9.9.0/24"}, inverse: true},
	)
	site := writeDat(t, dir, "geosite.dat",
		datEntry{code: "CN", domains: []Domain{
			{Type: DomainRoot, Value: "qq.com", Attrs: []string{"cn"}},
			{Type: DomainFull, Value: "Exact.CN"},
			{Type: DomainKeyword, Value: "baidu"},
			{Type: DomainRegexp, Value: `^api\d+\.example\.org$`, Attrs: []string{"cn", "api"}},
		}},
		datEntry{code: "GOOGLE", domains: []Domain{{Type: DomainRoot, Value: "google.com"}}},
	)
	return &GeoData{IPFile: ip, SiteFile: site}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":                        "example.com",
		"example.com.":                       "example.com",
		"example.com:443":                    "example.com",
		"https://user:pw@Example.com:8443/x": "example.com",
		"[2001:DB8::1]:443":                  "2001:db8::1",
		"2001:db8::1":                        "2001:db8::1",
		"fe80::1%eth0":                       "fe80::1",
		"192.0.2.1:80":                       "192.0.2.1",
		" host/path?q#f ":                    "host",
		"[::1":                               "",
		"":                                   "",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompileRules(t *testing.T) {
	m, err := Compile([]string{
		"# comment", "; comment", "",
		"192.0.2.1", "[2001:db8::7]:443", "10.0.0.0/8", "172.16.*", "2001:db8:1::/48",
		"full:Exact.example", "domain:root.example", "*sub.example", "*.only.example",
		"keyword:word", "plainkey", "regexp:^re[0-9]+\\.", "dotless:intra",
		"DOMAIN：upper.example",
	}, Options{})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if m.Len() != 14 || !m.HasIPRules() || !m.HasDomainRules() {
		t.Fatalf("Len() = %d", m.Len())
	}
	for addr, want := range map[string]bool{
		"192.0.2.1":                true,
		"192.0.2.2":                false,
		"[2001:db8::7]:80":         true,
		"10.255.0.1:22":            true,
		"::ffff:10.1.1.1":          true,
		"172.16.9.9":               true,
		"172.17.0.1":               false,
		"2001:db8:1:ff::1":         true,
		"exact.example":            true,
		"a.exact.example":          false,
		"root.example":             true,
		"a.b.root.example":         true,
		"xroot.example":            false,
		"sub.example":              true,
		"x.sub.example":            true,
		"only.example":             false,
		"x.only.example":           true,
		"swordfish.test":           true,
		"plainkey.net":             true,
		"re42.test":                true,
		"RE42.TEST:443":            true,
		"intranet":                 true,
		"intranet.local":           false,
		"upper.example":            true,
		"https://a.upper.example/": true,
		"other.test":               false,
		"":                         false,
	} {
		if got := m.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
	}
	if m.MatchDomain("192.0.2.1") || !m.MatchIP(netip.MustParseAddr("192.0.2.1")) {
		t.Error("MatchDomain/MatchIP mix up addresses and names")
	}
	dotless := MustCompile([]string{"dotless:"}, Options{})
	if !dotless.Match("localhost") || dotless.Match("a.b") {
		t.Error("dotless: without a value")
	}
	var nilMatcher *Matcher
	if nilMatcher.Match("x") || nilMatcher.MatchIP(netip.MustParseAddr("1.1.1.1")) || nilMatcher.Len() != 0 {
		t.Error("nil Matcher matched")
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		"10.*.1.*", "*.*", "foo*bar", "1.2.3.4/33", "full:", "domain:1.2.3.4", "regexp:(",
		"dotless:a.b", "geoip:", "geosite:", "geoip:cn", "ext:file", "ext::code", "keyword:a b",
	}
	m, err := Compile(append([]string{"192.0.2.1"}, bad...), Options{})
	if m == nil || err == nil {
		t.Fatalf("Compile() = %v, %v; want a Matcher and errors", m, err)
	}
	if m.Len() != 1 || !m.Match("192.0.2.1") {
		t.Fatalf("valid rule lost: Len() = %d", m.Len())
	}
	var ruleErrs []string
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		var re *RuleError
		if !errors.As(e, &re) {
			t.Fatalf("error %v is not a *RuleError", e)
		}
		ruleErrs = append(ruleErrs, re.Rule)
	}
	if !slices.Equal(ruleErrs, bad) {
		t.Fatalf("errors for %q, want %q", ruleErrs, bad)
	}
	var geoErr *RuleError
	if !errors.As(err, &geoErr) || !strings.Contains(err.Error(), `rule 11 "geoip:cn"`) {
		t.Fatalf("error text = %v", err)
	}
	if _, err := Compile([]string{"geoip:cn"}, Options{}); !errors.Is(err, ErrNoGeoData) {
		t.Fatalf("geoip without a file: %v, want %v", err, ErrNoGeoData)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustCompile did not panic")
		}
	}()
	MustCompile([]string{"full:"}, Options{})
}

func TestGeoRules(t *testing.T) {
	geo := testGeoData(t)
	dir := filepath.Dir(geo.IPFile)
	m, err := Compile([]string{"geoip:cn", "geoip:!us", "geosite:cn@api", "GEOSITE:google", "geoip:private"}, Options{GeoData: geo})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"1.2.3.4":           true,
		"[2001:db8::1]:443": true,
		"5.6.7.8":           true, // IPv4-mapped prefix in the file
		"8.8.8.8":           false,
		"9.9.9.9":           true, // not US
		"192.168.1.1":       true, // built-in private
		"api7.example.org":  true,
		"qq.com":            false, // lacks the api attribute
		"mail.google.com":   true,
	} {
		if got := m.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
	}
	// geoip:!us matches everything outside US, so restrict to US alone.
	us := MustCompile([]string{"geoip:us", "geoip:odd"}, Options{GeoData: geo})
	if !us.Match("8.8.8.8") || !us.Match("1.1.1.1") || us.Match("9.9.9.9") {
		t.Error("reverse_match entry not inverted")
	}

	site := MustCompile([]string{"geosite:cn"}, Options{GeoData: geo})
	for host, want := range map[string]bool{
		"qq.com": true, "www.qq.com": true, "exact.cn": true, "a.exact.cn": false,
		"news.baidu.com": true, "API1.example.org": true, "api.example.org": false,
	} {
		if got := site.Match(host); got != want {
			t.Errorf("geosite:cn Match(%q) = %v, want %v", host, got, want)
		}
	}

	// ext: reads either kind of file, relative to the default files.
	ext := MustCompile([]string{"ext:geoip.dat:cn", "ext:geosite.dat:google", "ext-ip:" + geo.IPFile + ":us", "ext-domain:geosite.dat:cn@cn"}, Options{GeoData: geo})
	for addr, want := range map[string]bool{"1.2.3.4": true, "8.8.8.8": true, "google.com": true, "qq.com": true, "exact.cn": false} {
		if got := ext.Match(addr); got != want {
			t.Errorf("ext Match(%q) = %v, want %v", addr, got, want)
		}
	}
	if _, err := Compile([]string{"ext:geosite.dat:cn@x@y", "ext:geoip.dat:cn@x", "ext:geosite.dat:!cn"}, Options{GeoData: &GeoData{Dir: dir}}); err == nil {
		t.Error("invalid ext: rules accepted")
	}
	if _, err := Compile([]string{"geoip:nope"}, Options{GeoData: geo}); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("unknown code error = %v", err)
	}
}

func TestGeoDataCodesAndReload(t *testing.T) {
	geo := testGeoData(t)
	codes, err := geo.Codes(geo.IPFile)
	if err != nil || !slices.Equal(codes, []string{"CN", "ODD", "US"}) {
		t.Fatalf("Codes() = %v, %v", codes, err)
	}
	if codes, _ := geo.Codes(""); !slices.Equal(codes, []string{"CN", "GOOGLE"}) {
		t.Fatalf("Codes(\"\") = %v, want the site file's", codes)
	}

	// A rewritten file is indexed again.
	if err := os.WriteFile(geo.IPFile, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(geo.IPFile, later, later); err != nil {
		t.Fatal(err)
	}
	if cn, err := geo.LoadIP("", "cn"); err != nil || len(cn.Prefixes) != 1 || cn.Prefixes[0].String() != "7.7.7.0/24" {
		t.Fatalf("LoadIP after rewrite = %v, %v", cn, err)
	}
	geo.Reset()
	if _, err := geo.LoadIP("", "us"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("LoadIP(us) after rewrite = %v", err)
	}

	// PRIVATE falls back to the built-in ranges.
	if p, err := (&GeoData{}).LoadIP("", "private"); err != nil || len(p.Prefixes) == 0 {
		t.Fatalf("built-in private = %v, %v", p, err)
	}
	if err := os.WriteFile(geo.IPFile, []byte{0x0a, 0x10, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := geo.LoadIP("", "cn"); !errors.Is(err, errProto) {
		t.Fatalf("truncated file error = %v", err)
	}
}

func TestSplitExt(t *testing.T) {
	for in, want := range map[string][2]string{
		"geo.dat:cn":                 {"geo.dat", "cn"},
		` C:\geo\site.dat : cn@ads `: {`C:\geo\site.dat`, "cn@ads"},
		"/a:b/geo.dat:!cn":           {"/a:b/geo.dat", "!cn"},
	} {
		file, code, err := splitExt(in)
		if err != nil || file != want[0] || code != want[1] {
			t.Errorf("splitExt(%q) = %q, %q, %v", in, file, code, err)
		}
	}
	for _, in := range []string{"geo.dat", ":cn", "geo.dat:"} {
		if _, _, err := splitExt(in); err == nil {
			t.Errorf("splitExt(%q) accepted", in)
		}
	}
}

func TestPolicy(t *testing.T) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com"}, Options{})
	for _, tt := range []struct {
		mode       Mode
		in, out    bool
		ip, notOut bool
	}{
		{Off, true, true, true, true},
		{Allowlist, true, false, true, false},
		{Denylist, false, true, false, true},
		{Mode(9), true, true, true, true},
	} {
		p := Policy{Mode: tt.mode, Rules: m}
		if p.Allows("www.example.com:443") != tt.in || p.Allows("other.test") != tt.out ||
			p.AllowsIP(netip.MustParseAddr("10.1.1.1")) != tt.ip || p.AllowsIP(netip.MustParseAddr("8.8.8.8")) != tt.notOut {
			t.Errorf("%v policy decided wrongly", tt.mode)
		}
	}
	if (Policy{Mode: Allowlist}).Allows("x") || !(Policy{Mode: Denylist}).Allows("x") {
		t.Error("policy without rules")
	}
	if Allowlist.String() != "allowlist" || Mode(9).String() != "mode 9" {
		t.Error("Mode.String")
	}
}

func TestSplitRules(t *testing.T) {
	got := SplitRules("a\r\n  b  \n\n# c\n")
	if !slices.Equal(got, []string{"a", "b", "# c"}) {
		t.Fatalf("SplitRules() = %q", got)
	}
}

// TestIPSetAgainstNaive compares the range set with a scan of the prefixes.
func TestIPSetAgainstNaive(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		var b ipSetBuilder
		var prefixes []netip.Prefix
		for range r.IntN(40) + 1 {
			var p netip.Prefix
			if r.IntN(2) == 0 {
				a := netip.AddrFrom4([4]byte{byte(r.IntN(4)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
				p = netip.PrefixFrom(a, r.IntN(33)).Masked()
			} else {
				var raw [16]byte
				raw[0], raw[15] = byte(r.IntN(3)), byte(r.IntN(256))
				p = netip.PrefixFrom(netip.AddrFrom16(raw), r.IntN(129)).Masked()
			}
			prefixes = append(prefixes, p)
			b.addPrefix(p)
		}
		set := b.build()
		for range 500 {
			var a netip.Addr
			if r.IntN(2) == 0 {
				a = netip.AddrFrom4([4]byte{byte(r.IntN(4)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
			} else {
				var raw [16]byte
				raw[0], raw[15] = byte(r.IntN(3)), byte(r.IntN(256))
				a = netip.AddrFrom16(raw)
			}
			want := slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
			if got := set.contains(a); got != want {
				t.Fatalf("contains(%v) = %v, want %v for %v", a, got, want, prefixes)
			}
		}
	}
	var b ipSetBuilder
	b.addPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	b.addPrefix(netip.MustParsePrefix("::/0"))
	b.addPrefix(netip.MustParsePrefix("255.255.255.255/32"))
	if set := b.build(); set.ranges() != 2 || !set.contains(netip.MustParseAddr("255.255.255.255")) || !set.contains(netip.IPv6Unspecified()) {
		t.Fatal("full ranges")
	}
}

// TestRealGeoData checks real files when GEOMATCH_GEOIP and GEOMATCH_GEOSITE
// name them.
func TestRealGeoData(t *testing.T) {
	ip, site := os.Getenv("GEOMATCH_GEOIP"), os.Getenv("GEOMATCH_GEOSITE")
	if ip == "" || site == "" {
		t.Skip("set GEOMATCH_GEOIP and GEOMATCH_GEOSITE to geoip.dat and geosite.dat")
	}
	geo := &GeoData{IPFile: ip, SiteFile: site}
	m, err := Compile([]string{"geoip:cn", "geosite:cn"}, Options{GeoData: geo})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{"223.5.5.5": true, "8.8.8.8": false, "qq.com": true, "www.baidu.com": true, "google.com": false} {
		if got := m.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
	}
	google := MustCompile([]string{"geosite:google", "geoip:private"}, Options{GeoData: geo})
	if !google.Match("www.google.com") || !google.Match("10.1.2.3") || google.Match("qq.com") {
		t.Error("geosite:google")
	}

	// Categories and attributes of common rule sets, including codes with !.
	rules := []string{
		"geosite:geolocation-!cn", "geosite:tld-!cn", "geosite:category-games@cn", "geosite:google@cn",
		"geosite:apple-cn", "geosite:china-list", "geosite:gfw", "geosite:private",
		"geoip:telegram", "geoip:cloudflare", "ext:" + site + ":tld-!cn",
	}
	m, err = Compile(rules, Options{GeoData: geo})
	if err != nil {
		t.Logf("not every category is in this file: %v", err)
	}
	for addr, want := range map[string]bool{"www.google.com": true, "149.154.167.50": true, "1.1.1.1": true, "localhost": true} {
		if got := m.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
	}

	// The built-in private ranges cover what the file's PRIVATE entry does.
	file, err := geo.LoadIP("", "private")
	if err != nil {
		t.Fatal(err)
	}
	var fb, bb ipSetBuilder
	for _, p := range file.Prefixes {
		fb.addPrefix(p)
	}
	for _, p := range privatePrefixes {
		bb.addPrefix(p)
	}
	if f, b := fb.build(), bb.build(); !slices.Equal(f.v4, b.v4) || !slices.Equal(f.v6, b.v6) {
		t.Errorf("built-in private ranges %v differ from the file's %v", b, f)
	}
	codes, err := geo.Codes(site)
	if err != nil || len(codes) < 100 {
		t.Fatalf("Codes() = %d codes, %v", len(codes), err)
	}
}
