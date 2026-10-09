package geomatch

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"testing"
)

func BenchmarkMatchIP(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 1))
	rules := make([]string, 0, 10000)
	for range 10000 {
		rules = append(rules, fmt.Sprintf("%d.%d.%d.0/24", r.IntN(224), r.IntN(256), r.IntN(256)))
	}
	m := MustCompile(rules, Options{})
	ip := netip.MustParseAddr("203.0.113.9")
	b.ReportAllocs()
	for b.Loop() {
		m.MatchIP(ip)
	}
}

func BenchmarkMatchDomain(b *testing.B) {
	rules := make([]string, 0, 50000)
	for i := range 50000 {
		rules = append(rules, fmt.Sprintf("domain:site%d.example", i))
	}
	rules = append(rules, "keyword:tracker", "keyword:ads")
	m := MustCompile(rules, Options{})
	b.ReportAllocs()
	for b.Loop() {
		m.MatchDomain("a.b.cdn.unknown.test")
	}
}

func BenchmarkMatchAddr(b *testing.B) {
	m := MustCompile([]string{"10.0.0.0/8", "domain:example.com"}, Options{})
	b.ReportAllocs()
	for b.Loop() {
		m.Match("www.example.com:443")
	}
}

// BenchmarkRealGeoData compiles and queries geoip:cn and geosite:cn from the
// files named by GEOMATCH_GEOIP and GEOMATCH_GEOSITE.
func BenchmarkRealGeoData(b *testing.B) {
	ip, site := os.Getenv("GEOMATCH_GEOIP"), os.Getenv("GEOMATCH_GEOSITE")
	if ip == "" || site == "" {
		b.Skip("set GEOMATCH_GEOIP and GEOMATCH_GEOSITE")
	}
	rules := []string{"geoip:cn", "geosite:cn"}
	b.Run("compile", func(b *testing.B) {
		for b.Loop() {
			MustCompile(rules, Options{GeoData: &GeoData{IPFile: ip, SiteFile: site}})
		}
	})
	m := MustCompile(rules, Options{GeoData: &GeoData{IPFile: ip, SiteFile: site}})
	b.Run("ip", func(b *testing.B) {
		addr := netip.MustParseAddr("223.5.5.5")
		for b.Loop() {
			m.MatchIP(addr)
		}
	})
	b.Run("domain", func(b *testing.B) {
		for b.Loop() {
			m.MatchDomain("www.unknown-site.com")
		}
	})
}
