package geomatch

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHostOfIgnoresEmbeddedScheme checks that a URL in a path or query does
// not stand in for the host, which would let it slip past a Policy.
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
