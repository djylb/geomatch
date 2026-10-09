// Package geomatch matches IP addresses and domain names against routing
// rules, including geoip: and geosite: rules backed by geoip.dat and
// geosite.dat files, for access control and traffic routing. It depends only
// on the standard library.
//
// Rules are compiled once into a Matcher, which is safe for concurrent use
// and answers a query with a binary search over merged address ranges, a
// hash table lookup per domain label, and a scan of any keywords and
// regular expressions:
//
//	geo := &geomatch.GeoData{IPFile: "geoip.dat", SiteFile: "geosite.dat"}
//	m, err := geomatch.Compile([]string{"geoip:cn", "geosite:cn", "10.0.0.0/8"}, geomatch.Options{GeoData: geo})
//	if err != nil {
//		log.Print(err) // the rules that were skipped; m holds the others
//	}
//	m.Match("example.cn:443")
//
// IP rules:
//
//	192.0.2.1, [2001:db8::1]   an address, optionally with a port
//	10.0.0.0/8, 2001:db8::/32  a CIDR prefix
//	10.*, 192.168.*.*          an IPv4 address whose trailing octets are *
//	geoip:cn                   an entry of GeoData.IPFile, by code
//	geoip:!cn                  every address outside that entry
//	geoip:private              private and special-use ranges, built in when
//	                           the file lacks them or there is no file
//	ext-ip:file.dat:code       an entry of another geoip file
//
// Domain rules, matched case-insensitively against the host:
//
//	full:example.com           exactly example.com
//	domain:example.com         example.com and its subdomains
//	*example.com               the same
//	*.example.com              the subdomains of example.com only
//	keyword:example, example   hosts containing the text
//	regexp:^ex.*\.com$         hosts matching the regular expression
//	dotless:, dotless:intra    hosts without a dot, or those containing the text
//	geosite:google             an entry of GeoData.SiteFile, by code
//	geosite:google@cn          the domains of that entry with every attribute
//	ext-domain:file.dat:code   an entry of another geosite file
//
// ext:file.dat:code reads an entry of either kind, telling the formats apart
// by their contents. Rule kinds are case-insensitive, a full-width colon is
// read as a colon, and lines starting with # or ; are comments. Hosts may be
// written as URLs or host:port.
//
// ParseRule reads one rule into a Rule without any geodata, to validate or
// normalize configuration, and CompileRules compiles parsed rules. A Policy
// turns a Matcher into an allowlist or a denylist, and MatchRule and
// Policy.Decide report the rule that matched.
package geomatch
