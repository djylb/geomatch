package geomatch

import (
	"bytes"
	"net/netip"
	"testing"
)

func FuzzCompileAndMatch(f *testing.F) {
	for _, s := range []string{"10.*", "192.168.0.0/16", "full:a.b", "*.x.y", "regexp:^a", "geoip:private", "ext:f:c@a", "[::1]:80", "dotless:"} {
		f.Add(s, "a.x.y:443")
	}
	f.Fuzz(func(t *testing.T, rule, addr string) {
		m, _ := Compile([]string{rule, "keyword:zz", "10.0.0.0/8"})
		// Find agrees with Match, which takes another path, in every form.
		if _, ok := m.Find(addr); ok != m.Match(addr) {
			t.Fatalf("rule %q: Find(%q) = %v, Match disagrees", rule, addr, ok)
		}
		if _, ok := m.FindDomain(addr); ok != m.MatchDomain(addr) {
			t.Fatalf("rule %q: FindDomain(%q) = %v, MatchDomain disagrees", rule, addr, ok)
		}
		ip, _ := netip.ParseAddr(addr)
		if _, ok := m.FindIP(ip); ok != m.MatchIP(ip) {
			t.Fatalf("rule %q: FindIP(%v) = %v, MatchIP disagrees", rule, ip, ok)
		}
		if _, ok := m.FindHostIP(addr, ip); ok != m.MatchHostIP(addr, ip) || ok != (m.MatchDomain(addr) || m.MatchIP(ip)) {
			t.Fatalf("rule %q: FindHostIP(%q, %v) = %v disagrees", rule, addr, ip, ok)
		}
		other := MustCompile([]string{"keyword:b", "10.1.0.0/16"})
		var policies []Policy
		for _, pr := range []Priority{DenyFirst, AllowFirst} {
			policies = append(policies, Policy{Allow: m, Priority: pr}, Policy{Deny: m, Priority: pr},
				Policy{Allow: m, Deny: other, Priority: pr}, Policy{Allow: other, Deny: m, Priority: pr})
		}
		for _, p := range policies {
			if d := p.Decide(addr); d.Allowed != p.Allows(addr) {
				t.Fatalf("rule %q: %+v Decide(%q) = %+v, Allows disagrees", rule, p, addr, d)
			}
		}
		for _, first := range []bool{false, true} {
			l := Levels{Policies: policies, FirstMatch: first, DenyUnmatched: len(rule)%2 == 0}
			d := l.Decide(addr)
			if d.Allowed != l.Allows(addr) || first && (d.Level == -1) == d.Matched {
				t.Fatalf("rule %q: Levels(FirstMatch %v).Decide(%q) = %+v, Allows %v", rule, first, addr, d, l.Allows(addr))
			}
		}
		r := Router[int]{Routes: []Route[int]{{Matcher: MustCompile([]string{"keyword:a"}), Target: 1}, {Matcher: m, Target: 2}}}
		if got := r.Find(addr); got.Target != r.Route(addr) || got.Matched != (got.Index >= 0) {
			t.Fatalf("rule %q: Router.Find(%q) = %+v, Route = %v", rule, addr, got, r.Route(addr))
		}
		_ = HostOf(addr)
	})
}

func FuzzDecodeGeoData(f *testing.F) {
	f.Add(encodeDat(datEntry{code: "CN", cidrs: []string{"1.2.3.0/24", "2001:db8::/32"}}))
	f.Add(encodeDat(datEntry{code: "X", domains: []Domain{{Type: DomainRoot, Value: "a.b", Attrs: []string{"c"}}, {Value: "kw"}}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		index, err := indexDat(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		for _, sp := range index {
			if sp.off < 0 || sp.n < 0 || sp.off+sp.n > int64(len(data)) {
				t.Fatalf("span %+v outside %d bytes", sp, len(data))
			}
			rec := data[sp.off : sp.off+sp.n]
			_, _ = decodeGeoIP(rec)
			_, _ = decodeGeoSite(rec)
			_ = recordKind(rec)
		}
	})
}
