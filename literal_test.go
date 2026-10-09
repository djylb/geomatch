package geomatch

import (
	"math/rand/v2"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestLiteralIndexAgainstContains(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "ab.c-"[r.IntN(5)]
		}
		return string(b)
	}
	for range 200 {
		lits := make([]string, r.IntN(8)+1)
		for i := range lits {
			lits[i] = word(r.IntN(4) + 1)
		}
		x := newLiteralIndex(lits)
		for range 50 {
			text := word(r.IntN(20))
			found := make([]bool, len(lits))
			x.scan(text, func(id int32) bool {
				found[id] = true
				return false
			})
			for i, lit := range lits {
				if found[i] != strings.Contains(text, lit) {
					t.Fatalf("literal %q in %q: found %v", lit, text, found[i])
				}
			}
		}
	}
}

func TestRequiredLiteral(t *testing.T) {
	for pattern, want := range map[string]string{
		`(^|\.)uu[a-z][1-9][0-9]?\.com$`:       "uu",
		`(^|\.)[a-z][1-9][0-9][a-z]\.com$`:     ".com",
		`(^|\.)13mei[5-7]\.buzz$`:              "13mei",
		`^[0-9]+vod-adaptive\.akamaized\.net$`: "vod-adaptive.akamaized.net",
		`^ad(s)?\.Example\.COM$`:               ".example.com",
		`^(foo|bar)\.com$`:                     ".com",
		`^ab?c`:                                "",
		`(abc)+x`:                              "abc",
		`x(?:yza){2,}`:                         "yza",
		`(?i)ſtraße`:                           "",
		`a|b`:                                  "",
		`(`:                                    "",
	} {
		if got := requiredLiteral(pattern); got != want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// TestRegexpPrefilter compares the prefiltered regular expressions with
// running all of them, on hosts made to hit and miss their literals.
func TestRegexpPrefilter(t *testing.T) {
	patterns := []string{`(^|\.)13mei[5-7]\.buzz$`, `^[0-9]+vod-adaptive\.akamaized\.net$`, `^ad(s)?\.example\.com$`, `^ab?c`, `straße`, `^x+$`}
	hosts := []string{"13mei6.buzz", "a.13mei5.buzz", "13mei8.buzz", "12vod-adaptive.akamaized.net", "vod-adaptive.akamaized.net",
		"ads.example.com", "ad.example.com", "abc", "ac.d", "straße", "STRASSE", "ſtraße", "xxx", "x", "unrelated.test"}
	if path := os.Getenv("GEOMATCH_GEOSITE"); path != "" {
		g := &GeoData{SiteFile: path}
		for _, code := range []string{"geolocation-!cn", "cn", "google", "category-ads-all"} {
			domains, err := g.LoadSite("", code)
			if err != nil {
				t.Fatal(err)
			}
			for i, d := range domains {
				if d.Type == DomainRegexp {
					patterns = append(patterns, d.Value)
				} else if i%50 == 0 {
					hosts = append(hosts, d.Value, "www."+d.Value, "x"+d.Value)
				}
			}
		}
	}
	var d domainSet
	var all []*regexp.Regexp
	for _, p := range patterns {
		if err := d.addRegexp(p); err != nil {
			t.Fatal(err)
		}
		all = append(all, regexp.MustCompile("(?i)"+p))
	}
	d.finish()
	for _, host := range hosts {
		host = HostOf(host)
		want := false
		for _, re := range all {
			if re.MatchString(host) {
				want = true
				break
			}
		}
		if got := d.match(host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
	t.Logf("%d patterns, %d with a literal, %d hosts", len(patterns), len(d.litOwner), len(hosts))
}
