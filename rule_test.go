package geomatch

import (
	"encoding/json"
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
		"https://Example.com/path":  "example.com",
		".Example.com":              ".example.com",
		"//Example.com/path":        "example.com",
		"keyword:Example.com":       "keyword:example.com",
		"full:例子.CN":                "full:xn--fsqu00a.cn",
		"*.Bücher.de":               "*.xn--bcher-kva.de",
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
		if _, err := ParseRule(in); !errors.Is(err, errNoRule) || !isComment(in) {
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
	})
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

func TestRuleText(t *testing.T) {
	var cfg struct {
		Mode  Mode
		Rules []Rule
	}
	in := `{"Mode":"denylist","Rules":["GEOIP:CN","*Example.com","10.1.2.3/8","regexp:^ads"]}`
	if err := json.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileRules(cfg.Rules[:1]); !errors.Is(err, ErrNoGeoData) {
		t.Fatalf("CompileRules(geoip:cn) without geodata = %v", err)
	}
	m, err := CompileRules(cfg.Rules[1:])
	if err != nil {
		t.Fatalf("CompileRules of decoded rules: %v", err)
	}
	if !m.Match("www.example.com") || !m.Match("10.9.9.9") {
		t.Fatalf("CompileRules of decoded rules = %v", m.Rules())
	}
	out, err := json.Marshal(cfg)
	if want := `{"Mode":"denylist","Rules":["geoip:cn","domain:example.com","10.0.0.0/8","regexp:^ads"]}`; err != nil || string(out) != want {
		t.Fatalf("json.Marshal = %s, %v; want %s", out, err, want)
	}
	if err := json.Unmarshal([]byte(`{"Rules":["full:"]}`), &cfg); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("invalid rule decoded: %v", err)
	}
	if _, err := json.Marshal([]Rule{{}}); err == nil {
		t.Error("zero Rule encoded")
	}
}

func TestLineEndingsAndBOM(t *testing.T) {
	want := []string{"domain:a.test", "", "# c", "10.0.0.0/8", "full:", "keyword:z"}
	for name, text := range map[string]string{
		"unix":    "\uFEFFdomain:a.test\n\n# c\n10.0.0.0/8\nfull:\nkeyword:z",
		"windows": "\uFEFFdomain:a.test\r\n\r\n# c\r\n10.0.0.0/8\r\nfull:\r\nkeyword:z",
		"old mac": "\uFEFFdomain:a.test\r\r# c\r10.0.0.0/8\rfull:\rkeyword:z",
		"mixed":   "domain:a.test\r\n\n# c\r10.0.0.0/8\nfull:\r\nkeyword:z",
	} {
		lines := SplitLines(text)
		if !reflect.DeepEqual(lines, want) {
			t.Errorf("%s: SplitLines = %q", name, lines)
		}
		m, err := Compile(lines)
		var errs RuleErrors
		if !errors.As(err, &errs) || len(errs) != 1 || errs[0].Index+1 != 5 || m.Len() != 3 || !m.Match("a.test") {
			t.Errorf("%s: Compile = %v, %v", name, m.Rules(), err)
		}
	}
	// A byte order mark is trimmed from a rule however the text was split.
	if r, err := ParseRule("\uFEFFdomain:a.test\r"); err != nil || r.String() != "domain:a.test" {
		t.Errorf("ParseRule with a BOM = %v, %v", r, err)
	}
	if !isComment("\uFEFF# c") || !isComment("\uFEFF") {
		t.Error("comment after a BOM")
	}
}
