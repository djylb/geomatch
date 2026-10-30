package geomatch

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

// Matchers that hold rules with ports.

func BenchmarkPortsMatchAddrPort(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 1))
	rules := make([]string, 0, 10000)
	for range 10000 {
		rules = append(rules, fmt.Sprintf("%d.%d.%d.0/24:%d", r.IntN(224), r.IntN(256), r.IntN(256), []int{22, 80, 443, 3389}[r.IntN(4)]))
	}
	m, err := Compile(rules)
	if err != nil {
		b.Fatal(err)
	}
	ap := netip.MustParseAddrPort("203.0.113.9:443")
	b.ReportAllocs()
	for b.Loop() {
		m.MatchAddrPort(ap)
	}
}

func BenchmarkPortsManyGroups(b *testing.B) {
	rules := make([]string, 0, 1000)
	for i := range 1000 {
		rules = append(rules, fmt.Sprintf("domain:site%d.example:%d-%d", i, 1000+i*10, 1005+i*10))
	}
	m, err := Compile(rules)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		m.Match("www.site500.example:6003")
	}
}

func BenchmarkPortsPolicyAllows(b *testing.B) {
	c := Compiler{}
	allow, _ := c.Compile([]string{"domain:example.com:443", "10.0.0.0/8:22,3389"})
	deny, _ := c.Compile([]string{"keyword:ads", "10.9.0.0/16:22"})
	p := Policy{Allow: allow, Deny: deny}
	b.ReportAllocs()
	for b.Loop() {
		p.Allows("www.example.com:443")
	}
}

func BenchmarkPortsDecide(b *testing.B) {
	c := Compiler{}
	rules := make([]string, 0, 20000)
	for i := range 20000 {
		rules = append(rules, fmt.Sprintf("domain:host%d.example:%d", i, 1+i%5))
	}
	m, _ := c.Compile(rules)
	p := Policy{Allow: m}
	b.ReportAllocs()
	for b.Loop() {
		p.Decide("www.host19999.example:5")
	}
}
