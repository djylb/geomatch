package geomatch_test

import (
	"fmt"
	"log"

	"github.com/djylb/geomatch"
)

func Example() {
	m, err := geomatch.Compile([]string{
		"10.0.0.0/8",
		"192.168.*",
		"domain:example.com",
		"*.internal.test",
		"geoip:private", // built in when no geoip.dat is configured
	}, geomatch.Options{})
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
func ExamplePolicy() {
	geo := &geomatch.GeoData{IPFile: "/etc/geodata/geoip.dat", SiteFile: "/etc/geodata/geosite.dat"}
	rules, err := geomatch.Compile(geomatch.SplitRules("geoip:cn\ngeoip:private\n"), geomatch.Options{GeoData: geo})
	if err != nil {
		log.Println(err) // rules that were skipped, for example a missing file
	}
	p := geomatch.Policy{Mode: geomatch.Allowlist, Rules: rules}
	fmt.Println(p.Allows("192.168.1.10:51234"))
}

func ExampleGeoData_Codes() {
	geo := &geomatch.GeoData{SiteFile: "/etc/geodata/geosite.dat"}
	codes, err := geo.Codes("")
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(len(codes), "geosite categories")
}
