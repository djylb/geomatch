package geomatch

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// replaceFile writes data next to path and renames it over path, as an
// update of a geodata file should.
func replaceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestLiveRefresh(t *testing.T) {
	geo := testGeoData(t)
	l, err := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn", "geosite:google", "10.0.0.0/8"})
	if err != nil || !l.Matcher().Match("1.2.3.4") || !l.Matcher().Match("google.com") {
		t.Fatalf("NewLive = %v", err)
	}
	if replaced, err := l.Refresh(); replaced || err != nil {
		t.Fatalf("Refresh without change = %v, %v", replaced, err)
	}

	// A new file, renamed over the old one.
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	old := l.Matcher()
	if replaced, err := l.Refresh(); !replaced || err != nil {
		t.Fatalf("Refresh after update = %v, %v", replaced, err)
	}
	if m := l.Matcher(); !m.Match("7.7.7.7") || m.Match("1.2.3.4") || !m.Match("google.com") || !m.Match("10.1.1.1") {
		t.Error("new geodata not in use")
	}
	if !old.Match("1.2.3.4") {
		t.Error("the previous Matcher changed")
	}

	// A broken file keeps the Matcher, and is not compiled again until it
	// changes.
	replaceFile(t, geo.Files().IP, []byte{0x0a, 0x10, 1})
	if replaced, err := l.Refresh(); replaced || !errors.Is(err, ErrGeoData) {
		t.Fatalf("Refresh with a broken file = %v, %v", replaced, err)
	}
	if !l.Matcher().Match("7.7.7.7") || l.Err() != nil {
		t.Error("broken file replaced the Matcher")
	}
	if replaced, err := l.Refresh(); replaced || err != nil {
		t.Fatalf("second Refresh with the same broken file = %v, %v", replaced, err)
	}

	// So does a removed file, and a good file again replaces it.
	if err := os.Remove(geo.Files().IP); err != nil {
		t.Fatal(err)
	}
	if replaced, err := l.Refresh(); replaced || !errors.Is(err, ErrGeoData) {
		t.Fatalf("Refresh with a removed file = %v, %v", replaced, err)
	}
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"8.8.4.0/24"}}))
	if replaced, err := l.Refresh(); !replaced || err != nil || !l.Matcher().Match("8.8.4.4") {
		t.Fatalf("Refresh after repair = %v, %v", replaced, err)
	}
}

func TestLiveMissingAtStart(t *testing.T) {
	dir := t.TempDir()
	geo := NewGeoData(GeoFiles{Site: filepath.Join(dir, "geosite.dat")})
	l, err := NewLive(Compiler{GeoData: geo}, []string{"geosite:cn", "domain:a.test"})
	if !errors.Is(err, ErrGeoData) || !l.Matcher().Match("a.test") || l.Err() == nil {
		t.Fatalf("NewLive without the file = %v", err)
	}
	// Still missing: the rule failed before too, so nothing to keep.
	if replaced, err := l.Refresh(); replaced || err != nil {
		t.Fatalf("Refresh, still missing = %v, %v", replaced, err)
	}
	replaceFile(t, geo.Files().Site, encodeDat(datEntry{code: "CN", domains: []Domain{{Type: DomainRoot, Value: "qq.com"}}}))
	if replaced, err := l.Refresh(); !replaced || err != nil || !l.Matcher().Match("qq.com") || l.Err() != nil {
		t.Fatalf("Refresh once the file appears = %v, %v", replaced, err)
	}
}

func TestLiveUpdate(t *testing.T) {
	geo := testGeoData(t)
	in := []string{"domain:a.test"}
	l, _ := NewLive(Compiler{GeoData: geo}, in)
	in[0] = "domain:changed.test"
	if got := l.Rules(); got[0] != "domain:a.test" {
		t.Fatalf("NewLive kept the caller's slice: %v", got)
	}
	err := l.Update([]string{"geosite:cn", "geoip:nope", "full:"})
	var errs RuleErrors
	if !errors.As(err, &errs) || len(errs) != 2 || l.Err() == nil {
		t.Fatalf("Update = %v", err)
	}
	if m := l.Matcher(); m.Match("a.test") || !m.Match("qq.com") || m.Len() != 1 {
		t.Error("Update did not replace the rules")
	}
	if err := l.Update(nil); err != nil || l.Matcher().Len() != 0 || l.Err() != nil {
		t.Errorf("Update(nil) = %v", err)
	}
}

func TestLiveWatch(t *testing.T) {
	geo := testGeoData(t)
	l, _ := NewLive(Compiler{GeoData: geo}, []string{"geosite:google"})
	if err := l.Watch(context.Background(), 0, nil); err == nil {
		t.Error("Watch accepted a zero interval")
	}
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan bool, 10)
	done := make(chan error)
	go func() {
		done <- l.Watch(ctx, time.Millisecond, func(replaced bool, err error) {
			if err != nil {
				t.Error(err)
			}
			reports <- replaced
		})
	}()
	replaceFile(t, geo.Files().Site, encodeDat(datEntry{code: "GOOGLE", domains: []Domain{{Type: DomainRoot, Value: "new.test"}}}))
	select {
	case replaced := <-reports:
		if !replaced || !l.Matcher().Match("new.test") {
			t.Error("Watch did not replace the Matcher")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not report")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Watch returned %v", err)
	}
}

func TestLiveConcurrent(t *testing.T) {
	geo := testGeoData(t)
	l, _ := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn", "geosite:cn"})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				m := l.Matcher()
				Policy{Allow: m}.Decide("qq.com")
				m.Match("1.2.3.4")
				// Block briefly so that the updates run where goroutines are
				// not preempted and file I/O waits for the event loop, as on
				// js/wasm.
				time.Sleep(10 * time.Microsecond)
			}
		})
	}
	for i := range 20 {
		cidr := "1.2.3.0/24"
		if i%2 == 1 {
			cidr = "5.5.5.0/24"
		}
		replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{cidr}}))
		if i%5 == 0 {
			_ = l.Update([]string{"geoip:cn", "geosite:cn"})
		}
		if _, err := l.Refresh(); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
	if !l.Matcher().Match("5.5.5.5") {
		t.Error("last update not in use")
	}
}

func TestPolicyFollowsLive(t *testing.T) {
	geo := testGeoData(t)
	l, _ := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn"})
	p := Policy{Deny: l}
	if p.Allows("1.2.3.4") {
		t.Fatal("denylist allows 1.2.3.4")
	}
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	if replaced, err := l.Refresh(); !replaced || err != nil {
		t.Fatal(replaced, err)
	}
	if !p.Allows("1.2.3.4") || p.Allows("7.7.7.7") || p.DecideIP(netip.MustParseAddr("7.7.7.7")).Rule.String() != "geoip:cn" {
		t.Error("Policy does not follow the Live")
	}
	var nilLive *Live
	if !(Policy{Deny: nilLive}).Allows("x") || !(Policy{Allow: nilLive}).Allows("x") || ModeAllowlist.Policy(nilLive).Allows("x") {
		t.Error("nil *Live")
	}

	// A list follows the Live as its rules come and go.
	empty, _ := NewLive(Compiler{GeoData: geo}, nil)
	allow := Policy{Allow: empty}
	mode := ModeAllowlist.Policy(empty)
	if allow.Allows("1.2.3.4") || mode.Allows("1.2.3.4") {
		t.Error("Live without rules allows")
	}
	if err := empty.Update([]string{"geoip:cn"}); err != nil {
		t.Fatal(err)
	}
	if allow.Allows("1.2.3.4") || mode.Allows("1.2.3.4") || !allow.Allows("7.7.7.7") || !mode.Allows("7.7.7.7") {
		t.Error("Live with rules")
	}
}

// TestRefreshLives checks that a GeoData refreshes the Lives compiled with it
// when their files change, and only then.
func TestRefreshLives(t *testing.T) {
	geo := testGeoData(t)
	// The Lives are dropped when the function returns.
	func() {
		c := Compiler{GeoData: geo}
		ips := make([]*Live, 3)
		for i := range ips {
			var err error
			if ips[i], err = NewLive(c, []string{"geoip:cn"}); err != nil {
				t.Fatal(err)
			}
		}
		sites, err := NewLive(c, []string{"geosite:google"})
		if err != nil {
			t.Fatal(err)
		}
		if r := geo.RefreshLives(); r.Changed() {
			t.Fatalf("RefreshLives without change = %+v", r)
		}

		replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
		if r := geo.RefreshLives(); len(r.Replaced) != 3 || len(r.Failed) != 0 || len(r.Errors) != 0 {
			t.Fatalf("RefreshLives = %+v; want the 3 geoip Lives replaced", r)
		}
		for _, l := range ips {
			if !l.Matcher().Match("7.7.7.7") {
				t.Fatal("geoip Live not refreshed")
			}
		}
		if !sites.Matcher().Match("google.com") {
			t.Fatal("geosite Live changed")
		}
		if r := geo.RefreshLives(); r.Changed() {
			t.Fatalf("second RefreshLives = %+v", r)
		}

	}()

	// Lives that the program dropped leave the list.
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		geo.RefreshLives()
		geo.lives.mu.Lock()
		n := len(geo.lives.lives)
		geo.lives.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d Lives kept after the program dropped them", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLiveRules checks Lives of parsed rules.
func TestLiveRules(t *testing.T) {
	geo := testGeoData(t)
	rules, err := ParseRules([]string{"geoip:cn", "DOMAIN:Example.com"})
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLiveRules(Compiler{GeoData: geo}, rules)
	if err != nil || !l.Matcher().Match("1.2.3.4") || !l.Matcher().Match("www.example.com") {
		t.Fatalf("NewLiveRules = %v", err)
	}
	rules[1].Value = "changed.test" // the Live keeps its own copy
	if got := l.Rules(); len(got) != 2 || got[1] != "domain:example.com" {
		t.Fatalf("Rules = %q", got)
	}
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	if replaced, err := l.Refresh(); !replaced || err != nil || !l.Matcher().Match("7.7.7.7") {
		t.Fatalf("Refresh = %v, %v", replaced, err)
	}
	if err := l.UpdateRules([]Rule{{Kind: RuleFull, Value: "only.test"}}); err != nil || !l.Matcher().Match("only.test") || l.Matcher().Match("7.7.7.7") {
		t.Fatalf("UpdateRules = %v", err)
	}
	if err := l.Update([]string{"10.0.0.0/8"}); err != nil || !l.Matcher().Match("10.1.1.1") || l.Rules()[0] != "10.0.0.0/8" {
		t.Fatalf("Update after UpdateRules = %v, %q", err, l.Rules())
	}
}

// TestRefreshLivesSeesFixedFiles checks that RefreshLives refreshes a Live
// whose file was broken or missing once the file is fixed, which the
// generation of the GeoData may not show.
func TestRefreshLivesSeesFixedFiles(t *testing.T) {
	geo := testGeoData(t)
	l, err := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn"})
	if err != nil {
		t.Fatal(err)
	}
	// Broken, then fixed.
	replaceFile(t, geo.Files().IP, []byte{0x0a, 0x10, 1})
	geo.RefreshLives()
	replaceFile(t, geo.Files().IP, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	for range 3 {
		geo.RefreshLives()
	}
	if !l.Matcher().Match("7.7.7.7") {
		t.Fatal("Live not refreshed after its broken file was fixed")
	}

	// Broken at the start.
	dir := t.TempDir()
	name := filepath.Join(dir, "late.dat")
	if err := os.WriteFile(name, []byte{0x0a, 0x10, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	geo2 := NewGeoData(GeoFiles{IP: name})
	late, err := NewLive(Compiler{GeoData: geo2}, []string{"geoip:cn"})
	if err == nil {
		t.Fatal("broken file compiled")
	}
	geo2.RefreshLives()
	replaceFile(t, name, encodeDat(datEntry{code: "CN", cidrs: []string{"8.8.8.0/24"}}))
	geo2.RefreshLives()
	if !late.Matcher().Match("8.8.8.8") {
		t.Fatal("Live with a file broken at the start not refreshed once fixed")
	}
}

// TestRefreshLivesSeesFixedPrivate checks a geoip:private rule whose file is
// broken at the start, for which the built-in ranges stand in, once the file
// is fixed.
func TestRefreshLivesSeesFixedPrivate(t *testing.T) {
	name := filepath.Join(t.TempDir(), "ip.dat")
	if err := os.WriteFile(name, []byte{0x0a, 0xff}, 0o600); err != nil { // cannot be indexed
		t.Fatal(err)
	}
	geo := NewGeoData(GeoFiles{IP: name})
	l, err := NewLive(Compiler{GeoData: geo}, []string{"geoip:private"})
	if err != nil || !l.Matcher().Match("10.1.1.1") {
		t.Fatalf("built-in private ranges: %v", err)
	}
	geo.RefreshLives()
	replaceFile(t, name, encodeDat(datEntry{code: "PRIVATE", cidrs: []string{"9.9.9.0/24"}}))
	geo.RefreshLives()
	if m := l.Matcher(); !m.Match("9.9.9.9") || m.Match("10.1.1.1") {
		t.Fatal("Live not refreshed once the private entry's file was fixed")
	}
}
