package geomatch_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/djylb/geomatch"
)

func Example() {
	m, err := geomatch.Compile([]string{
		"10.0.0.0/8",
		"192.168.*",
		"domain:example.com",
		"*.internal.test",
		"geoip:private", // built in when no geoip.dat is configured
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range []string{"10.1.2.3:22", "www.example.com:443", "internal.test", "db.internal.test", "172.16.0.1", "8.8.8.8"} {
		fmt.Println(addr, m.Match(addr))
	}
	// Output:
	// 10.1.2.3:22 true
	// www.example.com:443 true
	// internal.test false
	// db.internal.test true
	// 172.16.0.1 true
	// 8.8.8.8 false
}

// Allow only clients from China and private networks, by geodata files.
func ExampleCompiler_Compile() {
	geo := &geomatch.GeoData{IPFile: "/etc/geodata/geoip.dat", SiteFile: "/etc/geodata/geosite.dat"}
	text := "geoip:cn\ngeoip:private\n"
	m, err := geomatch.Compiler{GeoData: geo}.Compile(geomatch.SplitLines(text))
	if err != nil {
		log.Println(err) // rules that were skipped, for example for a missing file
	}
	p := geomatch.Policy{Allow: m}
	fmt.Println(p.Allows("192.168.1.10:51234"))
}

func ExampleGeoData_SiteCodes() {
	geo := &geomatch.GeoData{SiteFile: "/etc/geodata/geosite.dat"}
	codes, err := geo.SiteCodes("")
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(len(codes), "geosite categories")
}

func ExampleParseRule() {
	for _, s := range []string{"*Example.COM", "GEOSITE:Google@CN", "10.1.2.3/8", "foo*bar"} {
		r, err := geomatch.ParseRule(s)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(r)
	}
	// Output:
	// domain:example.com
	// geosite:google@cn
	// 10.0.0.0/8
	// geomatch: rule "foo*bar": a wildcard must be a leading * of a domain or trailing octets of an IPv4 address
}

// Check configuration lines without reading geodata, reporting errors by
// line number.
func ExampleParseRules() {
	text := "# rules\ndomain:example.com\nfull:\nfoo*bar\n"
	_, err := geomatch.ParseRules(geomatch.SplitLines(text))
	var errs geomatch.RuleErrors
	if errors.As(err, &errs) {
		for _, e := range errs {
			fmt.Printf("line %d: %v\n", e.Index+1, e.Err)
		}
	}
	// Output:
	// line 3: empty value
	// line 4: a wildcard must be a leading * of a domain or trailing octets of an IPv4 address
}

func ExampleMatcher_Find() {
	m := geomatch.MustCompile([]string{"keyword:ads", "domain:example.com", "10.0.0.0/8"})
	for _, addr := range []string{"ads.example.com", "www.example.com", "10.1.2.3:443", "8.8.8.8"} {
		rule, ok := m.Find(addr)
		fmt.Println(addr, rule, ok)
	}
	// Output:
	// ads.example.com keyword:ads true
	// www.example.com domain:example.com true
	// 10.1.2.3:443 10.0.0.0/8 true
	// 8.8.8.8  false
}

func ExamplePolicy_DecideNetAddr() {
	mode, _ := geomatch.ParseMode("blacklist")
	p := mode.Policy(geomatch.MustCompile([]string{"192.0.2.0/24"}))
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 51234}
	fmt.Println(mode, p.DecideNetAddr(remote))
	// Output: denylist denied by 192.0.2.0/24
}

// Accept rules from users without regular expressions or files outside the
// geodata directory, and tell their mistakes from missing data.
func ExampleCompiler() {
	c := geomatch.Compiler{
		Kinds:    geomatch.AllKinds.Without(geomatch.RuleRegexp),
		ExtFiles: geomatch.ExtLocal,
		Limits:   geomatch.Limits{MaxRules: 100},
	}
	_, err := c.Compile([]string{"domain:example.com", "regexp:^ads", "ext:/etc/geo.dat:cn", "geosite:cn"})
	var errs geomatch.RuleErrors
	if errors.As(err, &errs) {
		for _, e := range errs.Filter(geomatch.ErrInvalidRule) {
			fmt.Println("invalid:", e.Rule, "-", e.Err)
		}
		for _, e := range errs.Filter(geomatch.ErrGeoData) {
			fmt.Println("no data:", e.Rule)
		}
	}
	// Output:
	// invalid: regexp:^ads - rule kind not allowed: regexp
	// invalid: ext:/etc/geo.dat:cn - geodata file not allowed: /etc/geo.dat is not a local name
	// no data: geosite:cn
}

// Keep rules up to date with geodata files that are updated while the
// program runs.
func ExampleLive() {
	geo := &geomatch.GeoData{IPFile: "/etc/geodata/geoip.dat", SiteFile: "/etc/geodata/geosite.dat"}
	live, err := geomatch.NewLive(geomatch.Compiler{GeoData: geo}, []string{"geoip:cn", "geosite:cn"})
	if err != nil {
		log.Println(err) // rules that were skipped
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = live.Watch(ctx, time.Minute, func(replaced bool, err error) {
			log.Printf("geodata reloaded: %v, %v", replaced, err)
		})
	}()

	// The policy follows the Live as geodata changes.
	p := geomatch.Policy{Allow: live}
	fmt.Println(p.Allows("www.qq.com:443"))
}

// Route traffic by ordered rules; the first route that matches decides.
func ExampleRouter() {
	r := geomatch.Router[string]{
		Routes: []geomatch.Route[string]{
			{Matcher: geomatch.MustCompile([]string{"keyword:ads"}), Target: "block"},
			{Matcher: geomatch.MustCompile([]string{"domain:example.cn", "10.0.0.0/8"}), Target: "direct"},
		},
		Default: "proxy",
	}
	for _, addr := range []string{"ads.example.cn", "www.example.cn:443", "10.1.2.3", "example.com"} {
		fmt.Println(addr, r.Find(addr))
	}
	// Output:
	// ads.example.cn block by keyword:ads (route 0)
	// www.example.cn:443 direct by domain:example.cn (route 1)
	// 10.1.2.3 direct by 10.0.0.0/8 (route 1)
	// example.com proxy by default
}

// Deny a range but for an exception: with both lists, Priority decides for
// addresses on both.
func ExamplePolicy() {
	p := geomatch.Policy{
		Deny:     geomatch.MustCompile([]string{"192.0.2.0/24"}),
		Allow:    geomatch.MustCompile([]string{"192.0.2.7"}),
		Priority: geomatch.AllowFirst, // the exception wins; addresses on neither list are allowed
	}
	for _, addr := range []string{"192.0.2.7", "192.0.2.8", "198.51.100.1"} {
		fmt.Println(addr, p.Decide(addr))
	}
	// Output:
	// 192.0.2.7 allowed by 192.0.2.7
	// 192.0.2.8 denied by 192.0.2.0/24
	// 198.51.100.1 allowed: no rule matched
}

// Choose which list wins for addresses on both.
func ExamplePriority() {
	allow := geomatch.MustCompile([]string{"10.0.0.0/8"})
	deny := geomatch.MustCompile([]string{"10.9.0.0/16", "192.0.2.0/24"})
	for _, priority := range []geomatch.Priority{geomatch.DenyFirst, geomatch.AllowFirst} {
		p := geomatch.Policy{Allow: allow, Deny: deny, Priority: priority}
		fmt.Println(priority, p.Allows("10.1.1.1"), p.Allows("10.9.1.1"), p.Allows("192.0.2.1"), p.Allows("198.51.100.1"))
	}
	// Output:
	// deny-first true false false false
	// allow-first true true false true
}

// Every level must allow: a global denylist binds the levels after it.
func ExampleLevels() {
	levels := geomatch.Levels{Policies: []geomatch.Policy{
		{Deny: geomatch.MustCompile([]string{"geoip:private"})},             // global
		{Allow: geomatch.MustCompile([]string{"1.1.1.0/24", "8.8.8.0/24"})}, // user
		{Deny: geomatch.MustCompile([]string{"8.8.8.8"})},                   // tunnel
		{}, // a level that is not set changes nothing
	}}
	for _, addr := range []string{"1.1.1.1:443", "10.0.0.1", "8.8.8.8", "9.9.9.9"} {
		fmt.Println(addr, levels.Decide(addr))
	}
	// Output:
	// 1.1.1.1:443 allowed by 1.1.1.0/24 at level 1
	// 10.0.0.1 denied by geoip:private
	// 8.8.8.8 denied by 8.8.8.8 at level 2
	// 9.9.9.9 denied: no rule matched at level 1
}

// The first level whose rules match decides: here the global level
// overrides a user's, and the user's a tunnel's.
func ExampleLevels_firstMatch() {
	levels := geomatch.Levels{FirstMatch: true, Policies: []geomatch.Policy{
		{Allow: geomatch.MustCompile([]string{"10.1.0.0/16"})}, // global
		{Deny: geomatch.MustCompile([]string{"10.0.0.0/8"})},   // user
		{Allow: geomatch.MustCompile([]string{"10.2.0.0/16"})}, // tunnel
	}}
	for _, addr := range []string{"10.1.1.1", "10.2.1.1", "192.0.2.1"} {
		fmt.Println(addr, levels.Decide(addr))
	}
	// Output:
	// 10.1.1.1 allowed by 10.1.0.0/16
	// 10.2.1.1 denied by 10.0.0.0/8 at level 1
	// 192.0.2.1 allowed: no rule matched
}
