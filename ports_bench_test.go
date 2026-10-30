package geomatch

import (
	"net"
	"net/netip"
	"testing"
)

// The benchmarks without ports in their names query matchers that hold no
// port rule, the path that port conditions must leave as it was.

func BenchmarkPolicyAllows(b *testing.B) {
	p := Policy{Allow: MustCompile([]string{"domain:example.com", "10.0.0.0/8"}), Deny: MustCompile([]string{"keyword:ads", "10.9.0.0/16"})}
	b.ReportAllocs()
	for b.Loop() {
		p.Allows("www.example.com:443")
	}
}

func BenchmarkPolicyAllowsIP(b *testing.B) {
	p := Policy{Allow: MustCompile([]string{"domain:example.com", "10.0.0.0/8"}), Deny: MustCompile([]string{"keyword:ads", "10.9.0.0/16"})}
	ip := netip.MustParseAddr("10.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		p.AllowsIP(ip)
	}
}

func BenchmarkMatchNetAddr(b *testing.B) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com"})
	a := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		m.MatchNetAddr(a)
	}
}

func BenchmarkMatchAddrMiss(b *testing.B) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com", "keyword:ads"})
	b.ReportAllocs()
	for b.Loop() {
		m.Match("www.unknown.test:443")
	}
}

func BenchmarkFindAddr(b *testing.B) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com", "keyword:ads"})
	b.ReportAllocs()
	for b.Loop() {
		m.Find("www.example.com:443")
	}
}
