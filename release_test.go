package geomatch

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// eofFS returns files whose ReadAt reports io.EOF along with the last bytes,
// as io.ReaderAt allows.
type eofFS struct{ fs fstest.MapFS }

func (e eofFS) Open(name string) (fs.File, error) {
	f, err := e.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return eofFile{f}, nil
}

type eofFile struct{ fs.File }

func (f eofFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.File.(io.ReaderAt).ReadAt(p, off)
	fi, _ := f.Stat()
	if err == nil && off+int64(n) == fi.Size() {
		err = io.EOF
	}
	return n, err
}

func TestReadAtEOFWithFullRead(t *testing.T) {
	data := encodeDat(datEntry{code: "AA", cidrs: []string{"1.0.0.0/8"}}, datEntry{code: "ZZ", cidrs: []string{"2.0.0.0/8"}})
	geo := &GeoData{FS: eofFS{fstest.MapFS{"geoip.dat": {Data: data}}}, IPFile: "geoip.dat"}
	m, err := Compiler{GeoData: geo}.Compile([]string{"geoip:zz", "geoip:aa"})
	if err != nil || !m.Match("2.1.1.1") || !m.Match("1.1.1.1") {
		t.Fatalf("Compile with EOF on the last record = %v", err)
	}
}

func TestReadFullShort(t *testing.T) {
	short := shortReader{}
	if err := readFull(short, make([]byte, 4), 0); !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrGeoData) {
		t.Errorf("short read = %v", err)
	}
}

type shortReader struct{}

func (shortReader) ReadAt(p []byte, _ int64) (int, error) { return len(p) - 1, nil }

// TestStaleUnreadableFiles checks that a file that exists but cannot be
// used does not leave a Matcher stale until it changes.
func TestStaleUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.dat")
	if err := os.WriteFile(bad, []byte{0x0a, 0x10, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Compiler{GeoData: &GeoData{IPFile: bad}}.Compile([]string{"geoip:cn"})
	if !errors.Is(err, ErrGeoData) {
		t.Fatalf("malformed file error = %v", err)
	}
	if src := m.Sources(); len(src) != 1 || src[0].Missing || src[0].Size != 3 {
		t.Fatalf("Sources() = %+v", src)
	}
	if m.Stale() {
		t.Fatal("a malformed file that did not change makes the Matcher stale")
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(bad, later, later); err != nil {
		t.Fatal(err)
	}
	if !m.Stale() {
		t.Error("a changed malformed file does not make it stale")
	}

	// A directory exists but cannot be read as a file.
	m, _ = Compiler{GeoData: &GeoData{SiteFile: dir}}.Compile([]string{"geosite:cn"})
	if src := m.Sources(); len(src) != 1 || src[0].Missing || m.Stale() {
		t.Errorf("unreadable file: Sources() = %+v, Stale() = %v", src, m.Stale())
	}
}

func TestCodeNames(t *testing.T) {
	for _, s := range []string{"geoip:cn:x", "geosite:c n", "geosite:cn@a:b", "ext:f.dat:c\tn", "geoip:!c n"} {
		if _, err := ParseRule(s); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ParseRule(%q) = %v, want invalid", s, err)
		}
	}
	for _, s := range []string{"geosite:geolocation-!cn", "geosite:category-ads-all@ads", "ext:C:\\geo\\site.dat:tld-!cn"} {
		if _, err := ParseRule(s); err != nil {
			t.Errorf("ParseRule(%q) = %v", s, err)
		}
	}
}

// TestFileEntriesReleased checks that compiled entries of a file, such as
// those of attribute combinations that users wrote, go once no Matcher uses
// them, and are compiled again when needed.
func TestFileEntriesReleased(t *testing.T) {
	geo := testGeoData(t)
	compileMany := func() int {
		n := 0
		for i := range 20 {
			n += mustCompile(geo, []string{fmt.Sprintf("geosite:cn@x%d", i), "geoip:us"}).Len()
		}
		return n
	}
	entries := func() int {
		geo.mu.Lock()
		defer geo.mu.Unlock()
		n := 0
		for _, f := range geo.files {
			n += len(f.siteSets) + len(f.ipSets)
		}
		return n
	}
	if n := compileMany(); n != 40 {
		t.Fatalf("compiled %d rules, want 40", n)
	}
	if n := entries(); n == 0 || n > 21 {
		t.Fatalf("%d entries, want at most 21", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for entries() != 0 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if n := entries(); n != 0 {
		t.Fatalf("%d entries left after their Matchers went away", n)
	}
	if m := mustCompile(geo, []string{"geosite:cn", "geoip:us"}); !m.Match("qq.com") || !m.Match("8.8.8.8") {
		t.Error("entries not compiled again")
	}
}

// TestConcurrentUse runs compiles, queries, reloads and resets at once, for
// the race detector and to catch deadlocks.
func TestConcurrentUse(t *testing.T) {
	geo := testGeoData(t)
	shared := mustCompile(geo, []string{"geosite:cn", "geoip:cn", "regexp:^api", "keyword:x"})
	rulesets := [][]string{
		{"geosite:cn", "geosite:google", "geoip:cn", "geoip:us"},
		{"geoip:us", "geoip:cn", "geosite:google", "geosite:cn@cn"},
		{"ext:geosite.dat:cn", "ext:geoip.dat:!cn", "geoip:private"},
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				m, err := Compiler{GeoData: geo}.Compile(rulesets[(i+j)%len(rulesets)])
				if err != nil {
					t.Error(err)
					return
				}
				m.Match("qq.com")
				m.Find("1.2.3.4")
				m.Stale()
				shared.Find("api1.example.org")
				shared.MatchHostIP("x.test", netip.MustParseAddr("1.2.3.4"))
				Levels{Policies: []Policy{{Deny: shared}, {Allow: m}}}.Decide("qq.com")
				Levels{Policies: []Policy{{Deny: shared}, {Allow: m}}, FirstMatch: true}.Decide("qq.com")
				if j%10 == 0 {
					_, _ = geo.SiteCodes("")
					_, _ = geo.LoadIP("", "cn")
				}
				if i == 0 && j%25 == 0 {
					geo.Reset()
				}
				if j%20 == 0 {
					runtime.GC()
				}
			}
		})
	}
	wg.Wait()
	if !shared.Match("qq.com") || !shared.Match("1.2.3.4") {
		t.Error("shared Matcher changed")
	}
}
