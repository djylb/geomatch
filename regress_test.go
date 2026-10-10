package geomatch

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHostOfIgnoresEmbeddedScheme checks that a URL in a path or query does
// not stand in for the host, which would let it slip past a Policy.
//
//goland:noinspection HttpUrlsUsage
func TestHostOfIgnoresEmbeddedScheme(t *testing.T) {
	for in, want := range map[string]string{
		"blocked.com/login?next=https://allowed.com/": "blocked.com",
		"blocked.com?r=https://allowed.com":           "blocked.com",
		"http://ex%61mple.com/":                       "ex%61mple.com",
		"[fe80::1%25eth0]:80":                         "fe80::1",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
	p := Policy{Mode: Allowlist, Rules: MustCompile([]string{"domain:allowed.com"}, Options{})}
	if p.Allows("blocked.com/?r=https://allowed.com") {
		t.Fatal("allowlist bypassed through a URL in the query")
	}
}

func TestRuleValuesAreNotHosts(t *testing.T) {
	m := MustCompile([]string{"keyword:corp."}, Options{})
	if m.Match("corpus.example") || !m.Match("evilcorp.example") {
		t.Fatal("keyword: lost its trailing dot")
	}
	for _, rule := range []string{"domain:user@example.com", "full:example.com:443", "domain:exa%mple.com", "*.a/b"} {
		if _, err := Compile([]string{rule}, Options{}); err == nil {
			t.Errorf("Compile(%q) accepted a value that is not a host", rule)
		}
	}
}

// TestGeoDataPathsAsGiven checks that the public methods take file paths as
// given, relative to the working directory.
func TestGeoDataPathsAsGiven(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("conf", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("conf", "geoip.dat"), encodeDat(datEntry{code: "CN", cidrs: []string{"1.2.3.0/24"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	geo := &GeoData{IPFile: "conf/geoip.dat"}
	if codes, err := geo.Codes(geo.IPFile); err != nil || len(codes) != 1 {
		t.Fatalf("Codes(IPFile) = %v, %v", codes, err)
	}
	if _, err := geo.LoadIP(geo.IPFile, "cn"); err != nil {
		t.Fatalf("LoadIP(IPFile) error = %v", err)
	}
	// ext: names are relative to the default file's directory.
	if _, err := Compile([]string{"ext:geoip.dat:cn"}, Options{GeoData: geo}); err != nil {
		t.Fatalf("ext: next to IPFile: %v", err)
	}
	if _, err := Compile([]string{"ext:conf/geoip.dat:cn"}, Options{}); err != nil {
		t.Fatalf("ext: without GeoData: %v", err)
	}
}

// TestGeoDataReplacedFile checks that a file replaced by another with the
// same size and time is indexed again rather than read at old offsets.
func TestGeoDataReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	a := encodeDat(datEntry{code: "AA", domains: []Domain{{Type: DomainFull, Value: "one.test"}}}, datEntry{code: "BB", domains: []Domain{{Type: DomainFull, Value: "two.test"}}})
	b := encodeDat(datEntry{code: "BB", domains: []Domain{{Type: DomainFull, Value: "new.test"}}}, datEntry{code: "AA", domains: []Domain{{Type: DomainFull, Value: "old.test"}}})
	if len(a) != len(b) {
		t.Fatalf("test files differ in size: %d, %d", len(a), len(b))
	}
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.WriteFile(path, a, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, stamp, stamp)
	geo := &GeoData{SiteFile: path}
	if _, err := geo.Codes(""); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "next.dat")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(tmp, stamp, stamp)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if d, err := geo.LoadSite("", "bb"); err != nil || len(d) != 1 || d[0].Value != "new.test" {
		t.Fatalf("LoadSite after replacement = %v, %v", d, err)
	}
}

func TestIndexDatEdgeCases(t *testing.T) {
	// A code after the entries, a code longer than the read-ahead, an
	// unknown top-level field and a duplicate code, whose first entry wins.
	late := appendBytesField(nil, 2, appendBytesField(nil, 2, []byte("late.test")))
	late = appendBytesField(late, 1, []byte("LATE"))
	long := strings.Repeat("L", 700)
	var file []byte
	file = appendBytesField(file, 1, late)
	file = appendVarintField(file, 7, 42)
	file = append(file, encodeDat(
		datEntry{code: long, domains: []Domain{{Type: DomainFull, Value: "long.test"}}},
		datEntry{code: "dup", domains: []Domain{{Type: DomainFull, Value: "first.test"}}},
		datEntry{code: "DUP", domains: []Domain{{Type: DomainFull, Value: "second.test"}}},
	)...)
	index, err := indexDat(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"LATE", long, "DUP"} {
		if _, ok := index[code]; !ok {
			t.Errorf("code %.10q not indexed", code)
		}
	}
	path := filepath.Join(t.TempDir(), "site.dat")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := (&GeoData{SiteFile: path}).LoadSite("", "dup"); err != nil || d[0].Value != "first.test" {
		t.Fatalf("duplicate code = %v, %v; want the first entry", d, err)
	}
}

// TestExtEmptyGeoIP checks that ext: detects a geoip entry without CIDRs.
func TestExtEmptyGeoIP(t *testing.T) {
	path := writeDat(t, t.TempDir(), "ip.dat", datEntry{code: "ALL", inverse: true}, datEntry{code: "NONE"})
	all := MustCompile([]string{"ext:" + path + ":all"}, Options{})
	if !all.Match("192.0.2.1") {
		t.Fatal("reverse_match entry without CIDRs matched nothing")
	}
	if m := MustCompile([]string{"ext:" + path + ":!none"}, Options{}); !m.Match("192.0.2.1") {
		t.Fatal("negated empty entry matched nothing")
	}
}

// TestLiteralIndexLinearOutputs checks that nested literals do not copy
// output lists along fail links.
func TestLiteralIndexLinearOutputs(t *testing.T) {
	lits := make([]string, 2000)
	for i := range lits {
		lits[i] = strings.Repeat("a", i+1)
	}
	x := newLiteralIndex(lits)
	total := 0
	for _, n := range x.nodes {
		total += len(n.out)
	}
	if total != len(lits) {
		t.Fatalf("%d output entries for %d literals", total, len(lits))
	}
	hits := 0
	x.scan(strings.Repeat("a", 3), func(int32) bool { hits++; return false })
	if hits != 6 { // a three times, aa twice, aaa once
		t.Fatalf("%d hits, want 6", hits)
	}
}

// TestMatchersShareGeoEntries checks that Matchers compiled with one GeoData
// share each compiled geo entry, and that a changed file is compiled anew.
func TestMatchersShareGeoEntries(t *testing.T) {
	geo := testGeoData(t)
	rules := []string{"geosite:cn", "geosite:CN", "geoip:cn", "geoip:private", "domain:own.test"}
	a := MustCompile(rules, Options{GeoData: geo})
	b := MustCompile(rules, Options{GeoData: geo})
	// The domain rule is the Matcher's own; geosite:cn appears once, and
	// geoip:cn and geoip:private are merged into one shared set.
	if len(a.domSets) != 2 || len(a.ipSets) != 1 || a.domSets[1] != b.domSets[1] || a.ipSets[0] != b.ipSets[0] || a.domSets[0] == b.domSets[0] {
		t.Fatalf("entries not shared: %d domain sets, %d IP sets", len(a.domSets), len(a.ipSets))
	}
	if !a.Match("qq.com") || !a.Match("1.2.3.4") || !a.Match("10.0.0.1") || !a.Match("own.test") || a.Match("8.8.8.8") {
		t.Fatal("shared entries do not match")
	}
	if attr := MustCompile([]string{"geosite:cn@api"}, Options{GeoData: geo}); attr.domSets[0] == a.domSets[1] {
		t.Fatal("an attribute filter shares the unfiltered entry")
	}

	if err := os.WriteFile(geo.SiteFile, encodeDat(datEntry{code: "CN", domains: []Domain{{Type: DomainFull, Value: "new.cn"}}}), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(geo.SiteFile, later, later)
	c := MustCompile([]string{"geosite:cn"}, Options{GeoData: geo})
	if c.domSets[0] == a.domSets[1] || !c.Match("new.cn") || c.Match("qq.com") || !a.Match("qq.com") {
		t.Fatal("a changed file was not compiled anew, or an older Matcher changed")
	}
}

func TestGeoEntriesMergedPerMatcher(t *testing.T) {
	geo := testGeoData(t)
	a := MustCompile([]string{"geosite:cn", "geosite:google", "geoip:cn", "geoip:us"}, Options{GeoData: geo})
	b := MustCompile([]string{"geoip:us", "geoip:cn", "geosite:google", "geosite:cn"}, Options{GeoData: geo})
	if len(a.domSets) != 1 || len(a.ipSets) != 1 || a.domSets[0] != b.domSets[0] || a.ipSets[0] != b.ipSets[0] {
		t.Fatalf("not merged and shared: %d domain sets, %d IP sets", len(a.domSets), len(a.ipSets))
	}
	for addr, want := range map[string]bool{"qq.com": true, "mail.google.com": true, "1.2.3.4": true, "8.8.8.8": true, "9.9.9.9": false, "other.test": false} {
		if got := a.Match(addr); got != want {
			t.Errorf("Match(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestGeoDataPathsTrimmed(t *testing.T) {
	geo := testGeoData(t)
	spaced := &GeoData{IPFile: geo.IPFile + " ", SiteFile: " " + geo.SiteFile}
	if _, err := Compile([]string{"geoip:cn", "geosite:google"}, Options{GeoData: spaced}); err != nil {
		t.Fatalf("paths with spaces: %v", err)
	}
	if _, err := Compile([]string{"geoip:cn"}, Options{GeoData: &GeoData{IPFile: "  "}}); !errors.Is(err, ErrNoGeoData) {
		t.Fatalf("blank path error = %v, want %v", err, ErrNoGeoData)
	}
}

func TestPrivateFallbackOnBadRecord(t *testing.T) {
	// A PRIVATE record whose CIDR is cut short.
	rec := appendBytesField(nil, 1, []byte("PRIVATE"))
	rec = append(rec, 0x12, 0x10, 0x0a)
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, appendBytesField(nil, 1, rec), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Compile([]string{"geoip:private"}, Options{GeoData: &GeoData{IPFile: path}})
	if err != nil {
		t.Fatalf("geoip:private with a bad record: %v", err)
	}
	if !m.Match("10.0.0.1") {
		t.Fatal("geoip:private with a bad record does not match 10.0.0.1")
	}
}

// TestGeoKindMismatch checks that a rule naming the wrong kind of file fails
// and leaves the shared entries of correct rules intact.
func TestGeoKindMismatch(t *testing.T) {
	geo := testGeoData(t)
	for _, rule := range []string{"ext-ip:geosite.dat:google", "ext-domain:geoip.dat:cn", "ext:geosite.dat:!google"} {
		if _, err := Compile([]string{rule}, Options{GeoData: geo}); err == nil {
			t.Errorf("Compile(%q) accepted the wrong kind", rule)
		}
	}
	m := MustCompile([]string{"ext:geosite.dat:google", "ext:geoip.dat:cn"}, Options{GeoData: geo})
	if !m.Match("google.com") || !m.Match("1.2.3.4") || m.Match("8.8.8.8") {
		t.Fatal("correct ext: rules were poisoned by the wrong ones")
	}
}

// TestLeadingDotKeyword checks that a plain rule with a leading dot matches
// subdomains as a keyword, and not the domain itself.
func TestLeadingDotKeyword(t *testing.T) {
	m := MustCompile([]string{".example.com"}, Options{})
	if !m.Match("www.example.com") || m.Match("example.com") {
		t.Fatal(".example.com does not match subdomains only")
	}
}

// TestRulesCannotChangeMatcher checks that the rules a Matcher returns do
// not share memory with it.
func TestRulesCannotChangeMatcher(t *testing.T) {
	m := MustCompile([]string{"ext-domain:geosite.dat:cn@cn"}, Options{GeoData: testGeoData(t)})
	m.Rules()[0].Attrs[0] = "ads"
	r, ok := m.MatchRule("qq.com")
	r.Attrs[0] = "ads"
	if !ok || m.Rules()[0].String() != "ext-domain:geosite.dat:cn@cn" {
		t.Fatalf("rules changed through returned values: %v", m.Rules())
	}
	if r, _ := m.MatchRule("qq.com"); r.String() != "ext-domain:geosite.dat:cn@cn" {
		t.Fatalf("MatchRule = %v", r)
	}
}

// TestGeoDataDirFSReplaced checks that a file of an os.DirFS replaced by
// one of the same size and time is indexed again.
func TestGeoDataDirFSReplaced(t *testing.T) {
	dir := t.TempDir()
	name := writeDat(t, dir, "geoip.dat",
		datEntry{code: "AA", cidrs: []string{"1.2.3.0/24"}},
		datEntry{code: "BB", cidrs: []string{"5.6.7.0/24"}})
	geo := &GeoData{FS: os.DirFS(dir), IPFile: "geoip.dat"}
	if !MustCompile([]string{"geoip:aa"}, Options{GeoData: geo}).Match("1.2.3.4") {
		t.Fatal("geoip:aa does not match")
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	next := writeDat(t, dir, "next.dat",
		datEntry{code: "BB", cidrs: []string{"1.2.3.0/24"}},
		datEntry{code: "AA", cidrs: []string{"5.6.7.0/24"}})
	if err := os.Chtimes(next, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, name); err != nil {
		t.Fatal(err)
	}
	if m := MustCompile([]string{"geoip:aa"}, Options{GeoData: geo}); !m.Match("5.6.7.8") || m.Match("1.2.3.4") {
		t.Fatal("replaced file not indexed again")
	}
}
