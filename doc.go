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
//	c := geomatch.Compiler{GeoData: geo}
//	m, err := c.Compile([]string{"geoip:cn", "geosite:cn", "10.0.0.0/8"})
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
// Compile compiles rules without geodata. A Compiler reads geodata, and can
// allow only some rule kinds, keep ext: rules to local files and limit the
// rules, for rules that untrusted users write. ParseRule and ParseRules read
// rules into Rule values without any geodata, to validate or normalize
// configuration, and CompileRules compiles them. A skipped rule's error is
// an ErrInvalidRule, a fault of the rule, or an ErrGeoData, a fault of the
// geodata at hand. Matcher.Stale tells when geodata changed, and Live
// compiles rules again when it does, to update geodata while running.
//
// A Policy allows or denies addresses by an allowlist, a denylist, or both
// with a Priority, and Levels apply policies of several levels, such as
// global and per-user ones. A Router maps addresses to targets by ordered
// routes, the first that matches deciding, to route traffic. Their Decide
// and Find methods report the rule that decided.
package geomatch
