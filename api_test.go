package geomatch

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"runtime"
	"testing"
	"testing/fstest"
	"time"
)

func TestMatchRuleAndDecide(t *testing.T) {
	geo := testGeoData(t)
	m := MustCompile([]string{"keyword:qq", "geosite:cn", "10.0.0.0/8", "geoip:!us", "regexp:^api", "*.only.test"}, Options{GeoData: geo})
	for addr, want := range map[string]string{
		"www.qq.com":       "keyword:qq",
		"exact.cn":         "geosite:cn",
		"10.1.1.1:22":      "10.0.0.0/8",
		"1.1.1.1":          "geoip:!us",
		"api7.example.org": "geosite:cn", // geosite:cn comes first and holds it
		"apis.test":        "regexp:^api",
		"x.only.test":      "*.only.test",
	} {
		r, ok := m.MatchRule(addr)
		if !ok || r.String() != want {
			t.Errorf("MatchRule(%q) = %v, %v; want %s", addr, r, ok, want)
		}
	}
	if r, ok := m.MatchRule("8.8.8.8"); ok {
		t.Errorf("MatchRule(8.8.8.8) = %v", r)
	}
	if len(m.Rules()) != 6 || m.Rules()[1].String() != "geosite:cn" {
		t.Errorf("Rules() = %v", m.Rules())
	}

	deny := Policy{Mode: Denylist, Rules: m}
	if d := deny.Decide("www.qq.com"); d.Allowed || !d.Matched || d.Rule.String() != "keyword:qq" {
		t.Errorf("Denylist Decide = %+v", d)
	}
	if d := deny.Decide("8.8.8.8"); !d.Allowed || d.Matched {
		t.Errorf("Denylist Decide(8.8.8.8) = %+v", d)
	}
	allow := Policy{Mode: Allowlist, Rules: m}
	if d := allow.Decide("10.2.2.2"); !d.Allowed || d.Rule.String() != "10.0.0.0/8" {
		t.Errorf("Allowlist Decide = %+v", d)
	}
	if d := (Policy{}).Decide("x"); !d.Allowed || d.Matched {
		t.Errorf("Off Decide = %+v", d)
	}
	var nilMatcher *Matcher
	if _, ok := nilMatcher.MatchRule("x"); ok || nilMatcher.Rules() != nil {
		t.Error("nil Matcher")
	}
}

func TestMatchNetAddr(t *testing.T) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com", "dotless:", "keyword:abstract"}, Options{})
	for _, tt := range []struct {
		addr net.Addr
		want bool
	}{
		{&net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 80}, true},
		{&net.UDPAddr{IP: net.ParseIP("::ffff:10.1.2.3"), Port: 53}, true},
		{&net.IPAddr{IP: net.ParseIP("10.9.9.9")}, true},
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}, false},
		{(*net.TCPAddr)(nil), false},
		{(*net.IPAddr)(nil), false},
		{nil, false},
		{(*net.UnixAddr)(nil), false},
		{&net.UnixAddr{Name: "@abstract", Net: "unix"}, false},
		{&net.UnixAddr{Name: "sock", Net: "unixgram"}, false},
		{stringAddr("www.example.com:443"), true},
	} {
		if got := m.MatchNetAddr(tt.addr); got != tt.want {
			t.Errorf("MatchNetAddr(%v) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	p := Policy{Mode: Denylist, Rules: m}
	if p.AllowsNetAddr(&net.TCPAddr{IP: net.ParseIP("10.0.0.1")}) || !p.AllowsNetAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.1")}) ||
		!(Policy{}).AllowsNetAddr(nil) || (Policy{Mode: Allowlist}).AllowsNetAddr(nil) {
		t.Error("AllowsNetAddr")
	}
}

type stringAddr string

func (stringAddr) Network() string  { return "test" }
func (a stringAddr) String() string { return string(a) }

func TestModeText(t *testing.T) {
	for in, want := range map[string]Mode{
		"off": Off, "": Off, " NONE ": Off, "0": Off, "disabled": Off,
		"allowlist": Allowlist, "Whitelist": Allowlist, "allow": Allowlist, "1": Allowlist,
		"denylist": Denylist, "BLACKLIST": Denylist, "blocklist": Denylist, "deny": Denylist, "2": Denylist,
	} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseMode("maybe"); err == nil {
		t.Error("ParseMode accepted an unknown mode")
	}
	var cfg struct{ Mode Mode }
	if err := json.Unmarshal([]byte(`{"Mode":"whitelist"}`), &cfg); err != nil || cfg.Mode != Allowlist {
		t.Fatalf("json.Unmarshal = %v, %v", cfg.Mode, err)
	}
	if b, err := json.Marshal(cfg); err != nil || string(b) != `{"Mode":"allowlist"}` {
		t.Fatalf("json.Marshal = %s, %v", b, err)
	}
	for in, want := range map[string]Mode{`2`: Denylist, `0`: Off, `"\u0064eny"`: Denylist, `null`: Allowlist} {
		cfg.Mode = Allowlist
		if err := json.Unmarshal([]byte(`{"Mode":`+in+`}`), &cfg); err != nil || cfg.Mode != want {
			t.Errorf("json.Unmarshal(%s) = %v, %v; want %v", in, cfg.Mode, err, want)
		}
	}
	for _, in := range []string{`3`, `true`, `1.5`, `"\x"`, `[]`} {
		if err := json.Unmarshal([]byte(`{"Mode":`+in+`}`), &cfg); err == nil {
			t.Errorf("json.Unmarshal(%s) accepted", in)
		}
	}
	cfg.Mode = Allowlist
	if _, err := Mode(9).MarshalText(); err == nil {
		t.Error("MarshalText accepted an unknown mode")
	}
	if err := cfg.Mode.UnmarshalText([]byte("x")); err == nil || cfg.Mode != Allowlist {
		t.Error("UnmarshalText of an unknown mode changed the mode")
	}
}

func TestGeoDataFS(t *testing.T) {
	ip := encodeDat(datEntry{code: "CN", cidrs: []string{"1.2.3.0/24"}})
	site := encodeDat(datEntry{code: "CN", domains: []Domain{{Type: DomainRoot, Value: "qq.com"}}})
	mfs := fstest.MapFS{
		"geo/geoip.dat":   {Data: ip, ModTime: time.Unix(1, 0)},
		"geo/geosite.dat": {Data: site, ModTime: time.Unix(1, 0)},
		"geo/extra.dat":   {Data: site, ModTime: time.Unix(1, 0)},
	}
	geo := &GeoData{FS: mfs, IPFile: "geo/geoip.dat", SiteFile: "./geo/geosite.dat"}
	m, err := Compile([]string{"geoip:cn", "geosite:cn", "ext:extra.dat:cn"}, Options{GeoData: geo})
	if err != nil {
		t.Fatalf("Compile from FS: %v", err)
	}
	if !m.Match("1.2.3.4") || !m.Match("www.qq.com") {
		t.Fatal("rules from FS do not match")
	}

	// A changed file is read again.
	mfs["geo/geoip.dat"] = &fstest.MapFile{Data: encodeDat(datEntry{code: "CN", cidrs: []string{"5.6.7.0/24"}}), ModTime: time.Unix(2, 0)}
	if m := MustCompile([]string{"geoip:cn"}, Options{GeoData: geo}); !m.Match("5.6.7.8") || m.Match("1.2.3.4") {
		t.Fatal("changed FS file not read again")
	}

	// Files without ReadAt are read whole, once per version.
	plain := &countingFS{fs: mfs}
	geo = &GeoData{FS: plain, SiteFile: "geo/geosite.dat"}
	for range 3 {
		if m := MustCompile([]string{"geosite:cn"}, Options{GeoData: geo}); !m.Match("qq.com") {
			t.Fatal("FS without ReadAt")
		}
	}
	if plain.reads != 1 {
		t.Fatalf("file read %d times, want once", plain.reads)
	}
	if _, err := Compile([]string{"geoip:cn"}, Options{GeoData: &GeoData{FS: mfs, IPFile: "missing.dat"}}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing FS file error = %v", err)
	}
}

// countingFS hides ReadAt from its files and counts whole reads.
type countingFS struct {
	fs    fs.FS
	reads int
}

func (c *countingFS) Open(name string) (fs.File, error) {
	f, err := c.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &readOnlyFile{f: f, c: c}, nil
}

type readOnlyFile struct {
	f    fs.File
	c    *countingFS
	read bool
}

func (r *readOnlyFile) Stat() (fs.FileInfo, error) { return r.f.Stat() }
func (r *readOnlyFile) Close() error               { return r.f.Close() }
func (r *readOnlyFile) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		r.c.reads++
	}
	return r.f.Read(p)
}

// TestMergedEntriesReleased checks that a merged combination of entries is
// dropped from the cache once no Matcher uses it.
func TestMergedEntriesReleased(t *testing.T) {
	geo := testGeoData(t)
	m := MustCompile([]string{"geosite:cn", "geosite:google"}, Options{GeoData: geo})
	if !m.Match("google.com") {
		t.Fatal("merged entry does not match")
	}
	count := func() int {
		geo.mu.Lock()
		defer geo.mu.Unlock()
		return len(geo.siteCombos)
	}
	if count() != 1 {
		t.Fatalf("%d cached combinations, want 1", count())
	}
	runtime.KeepAlive(m)
	m = nil
	deadline := time.Now().Add(5 * time.Second)
	for count() != 0 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if n := count(); n != 0 {
		t.Fatalf("%d cached combinations after the Matcher went away", n)
	}
}
