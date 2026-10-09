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
		m, _ := Compile([]string{rule}, Options{})
		m.Match(addr)
		m.MatchDomain(addr)
		if ip, err := netip.ParseAddr(addr); err == nil {
			m.MatchIP(ip)
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
