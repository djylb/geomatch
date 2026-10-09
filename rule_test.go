package geomatch

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestParseRule(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:80":              "192.0.2.1",
		"[2001:DB8::1]:443":         "2001:db8::1",
		"::ffff:10.0.0.0/104":       "10.0.0.0/8",
		"10.1.2.3/8":                "10.0.0.0/8",
		"10.*":                      "10.0.0.0/8",
		"GEOIP:!CN":                 "geoip:!cn",
		"ext-ip：ip.dat:cn":          "ext-ip:ip.dat:cn",
		"geosite:Google@CN@ads@cn":  "geosite:google@ads@cn",
		"ext-domain:site.dat:apple": "ext-domain:site.dat:apple",
		"ext:C:\\geo\\x.dat:!cn":    "ext:C:\\geo\\x.dat:!cn",
		"full:Example.COM.":         "full:example.com",
		"domain:example.com":        "domain:example.com",
		"*example.com":              "domain:example.com",
		"*.example.com":             "*.example.com",
		"keyword:Corp.":             "keyword:corp.",
		"https://Example.com/path":  "keyword:example.com",
		".Example.com":              "keyword:.example.com",
		"regexp:^A+$":               "regexp:^A+$",
		"dotless:":                  "dotless:",
		"dotless:Intra":             "dotless:intra",
	} {
		r, err := ParseRule(in)
		if err != nil {
			t.Errorf("ParseRule(%q) error = %v", in, err)
			continue
		}
		if got := r.String(); got != want {
			t.Errorf("ParseRule(%q).String() = %q, want %q", in, got, want)
		}
		back, err := ParseRule(r.String())
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Errorf("ParseRule(%q) round trip = %+v, %v; want %+v", r.String(), back, err, r)
		}
	}
	for _, in := range []string{"", "  ", "# c", "; c"} {
		if _, err := ParseRule(in); !errors.Is(err, errNoRule) || !IsComment(in) {
			t.Errorf("ParseRule(%q) error = %v, want a comment", in, err)
		}
	}
	for _, in := range []string{"geoip:cn@x", "ext:f.dat:!cn@x", "geosite:", "regexp:(", "full:a b"} {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) accepted", in)
		}
	}
	ip, _ := ParseRule("10.0.0.0/8")
	dom, _ := ParseRule("domain:a.b")
	ext, _ := ParseRule("ext:f.dat:x")
	if !ip.IsIP() || ip.IsDomain() || dom.IsIP() || !dom.IsDomain() || !ext.IsIP() || !ext.IsDomain() {
		t.Error("IsIP/IsDomain")
	}
	if got := (Rule{Kind: 99}).String(); got != "rule kind 99" {
		t.Errorf("unknown kind String() = %q", got)
	}
}

func TestCompileRulesNormalizes(t *testing.T) {
	m, err := CompileRules([]Rule{
		{Kind: RuleDomain, Value: "Example.COM."},
		{Kind: RuleIP, Prefix: netip.MustParsePrefix("10.1.2.3/8")},
		{Kind: RuleFull, Value: "bad host"},
	}, Options{})
	var re *RuleError
	if !errors.As(err, &re) || re.Index != 2 {
		t.Fatalf("error = %v, want rule 2 rejected", err)
	}
	if !m.Match("www.example.com") || !m.Match("10.9.9.9") || m.Len() != 2 {
		t.Fatalf("normalized rules did not match: %v", m.Rules())
	}
}

func FuzzParseRule(f *testing.F) {
	for _, s := range []string{"10.*", "geosite:a@b", "ext:x:!c", "*.a.b", "regexp:x{2}", "[::1]:80", "keyword:Q"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRule(s)
		if err != nil {
			return
		}
		back, err := ParseRule(r.String())
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("round trip of %q: %+v -> %q -> %+v, %v", s, r, r.String(), back, err)
		}
	})
}
