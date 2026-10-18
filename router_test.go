package geomatch

import (
	"net"
	"net/netip"
	"testing"
)

func TestRouterACL(t *testing.T) {
	acl := Router[bool]{
		Routes: []Route[bool]{
			{Matcher: MustCompile([]string{"192.0.2.7", "domain:ok.blocked.test"}), Target: true},
			{Matcher: MustCompile([]string{"192.0.2.0/24", "domain:blocked.test"}), Target: false},
		},
		Default: true,
	}
	for addr, want := range map[string]bool{
		"192.0.2.7":           true, // the exception comes first
		"192.0.2.8":           false,
		"ok.blocked.test:443": true,
		"x.blocked.test":      false,
		"198.51.100.1":        true, // by default
	} {
		if got := acl.Route(addr); got != want {
			t.Errorf("Route(%q) = %v, want %v", addr, got, want)
		}
		if got := acl.Find(addr); got.Target != want {
			t.Errorf("Find(%q) = %+v, want %v", addr, got, want)
		}
	}
}

func TestRouterTargets(t *testing.T) {
	geo := testGeoData(t)
	r := Router[string]{
		Routes: []Route[string]{
			{Matcher: MustCompile([]string{"keyword:ads"}), Target: "block"},
			{Matcher: nil, Target: "never"},
			{Matcher: mustCompile(geo, []string{"geosite:cn", "geoip:cn"}), Target: "direct"},
			{Matcher: mustCompile(geo, []string{"geosite:google"}), Target: "proxy"},
		},
		Default: "proxy",
	}
	cases := []struct {
		addr, target, rule string
		index              int
	}{
		{"ads.qq.com", "block", "keyword:ads", 0},
		{"www.qq.com", "direct", "geosite:cn", 2},
		{"1.2.3.4:443", "direct", "geoip:cn", 2},
		{"google.com", "proxy", "geosite:google", 3},
		{"other.test", "proxy", "", -1},
	}
	for _, c := range cases {
		got := r.Find(c.addr)
		if got.Target != c.target || got.Index != c.index || got.Matched != (c.index >= 0) || got.Rule.String() != c.rule {
			t.Errorf("Find(%q) = %+v, want %s by %q at %d", c.addr, got, c.target, c.rule, c.index)
		}
		if r.Route(c.addr) != c.target {
			t.Errorf("Route(%q) != %s", c.addr, c.target)
		}
	}
	if s := r.Find("google.com").String(); s != "proxy by geosite:google (route 3)" {
		t.Errorf("String() = %q", s)
	}
	if s := r.Find("other.test").String(); s != "proxy by default" {
		t.Errorf("String() = %q", s)
	}

	ip := netip.MustParseAddr("1.2.3.4")
	tcp := &net.TCPAddr{IP: ip.AsSlice(), Port: 1}
	if r.RouteIP(ip) != "direct" || r.RouteNetAddr(tcp) != "direct" || r.RouteHostIP("other.test", ip) != "direct" ||
		r.RouteDomain("1.2.3.4") != "proxy" || r.RouteDomain("ads.test") != "block" {
		t.Error("Route forms")
	}
	if r.FindIP(ip).Index != 2 || r.FindNetAddr(tcp).Index != 2 || r.FindHostIP("ads.test", ip).Index != 0 ||
		r.FindDomain("www.qq.com").Index != 2 {
		t.Error("Find forms")
	}
	var zero Router[int]
	if zero.Route("x") != 0 || zero.Find("x").Index != -1 {
		t.Error("zero Router")
	}
}

func TestRouterFollowsLive(t *testing.T) {
	geo := testGeoData(t)
	l, _ := NewLive(Compiler{GeoData: geo}, []string{"geoip:cn"})
	r := Router[string]{Routes: []Route[string]{{Matcher: l, Target: "direct"}}, Default: "proxy"}
	if r.Route("1.2.3.4") != "direct" {
		t.Fatal("before update")
	}
	replaceFile(t, geo.IPFile, encodeDat(datEntry{code: "CN", cidrs: []string{"7.7.7.0/24"}}))
	if _, err := l.Refresh(); err != nil {
		t.Fatal(err)
	}
	if r.Route("1.2.3.4") != "proxy" || r.Route("7.7.7.7") != "direct" {
		t.Error("Router does not follow the Live")
	}
}
