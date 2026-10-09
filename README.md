# geomatch

Match IP addresses and domain names against routing rules, including
`geoip:` and `geosite:` rules backed by `geoip.dat` and `geosite.dat` files,
for access control and traffic routing in Go.

- No dependencies beyond the standard library, and builds on every Go port.
- Rules compile into a `Matcher` safe for concurrent use; queries of lowercase
  hosts do not allocate.
- Geodata files are indexed on first use, so a rule reads only its own entry
  of a file of tens of megabytes, and files changed on disk are picked up.
- Matchers compiled with one `GeoData` share each compiled `geoip:` and
  `geosite:` entry, so many policies that use `geosite:cn` hold it once.
- Geodata can come from the file system or any `fs.FS`, such as an
  `embed.FS`.

## Install

```bash
go get github.com/djylb/geomatch
```

## Usage

```go
func newMatcher(geo *geomatch.GeoData) *geomatch.Matcher {
	m, err := geomatch.Compile([]string{
		"geoip:cn",
		"geosite:cn",
		"10.0.0.0/8",
		"domain:example.com",
	}, geomatch.Options{GeoData: geo})
	if err != nil {
		// Invalid rules, or rules whose geodata could not be read, were
		// skipped; m holds the others. Each is a *geomatch.RuleError with
		// the rule's index.
		log.Print(err)
	}
	return m
}

func route(m *geomatch.Matcher, target string) string {
	if m.Match(target) { // "www.example.com:443", "10.1.2.3", "https://host/path"
		return "direct"
	}
	return "proxy"
}
```

`MatchIP` takes a `netip.Addr`, `MatchNetAddr` a `net.Addr` such as a
connection's `RemoteAddr` (without formatting it), and `MatchDomain` a host
name that is never read as an IP address. `HostOf` extracts the host that
`Match` uses from an address or URL. Hosts and rules are ASCII: write
internationalized names in their `xn--` form, as geosite files do.

### Policies

A `Policy` turns a `Matcher` into an allowlist or a denylist. `Decide` also
reports the rule that decided, for logs:

```go
func checkClient(p geomatch.Policy, remote net.Addr) bool {
	d := p.Decide(remote.String())
	if !d.Allowed && d.Matched {
		log.Printf("%v denied by %v", remote, d.Rule)
	}
	return d.Allowed
}
```

`Mode` reads and writes its name in configuration files (`"allowlist"`,
`"denylist"`, `"off"`). It also reads `whitelist`, `blacklist`, `allow`,
`deny` and the numbers `0` to `2`, which JSON may give as numbers.

### Geodata

```go
//go:embed geo/geoip.dat geo/geosite.dat
var geoFiles embed.FS

var geo = &geomatch.GeoData{FS: geoFiles, IPFile: "geo/geoip.dat", SiteFile: "geo/geosite.dat"}
```

Without `FS`, the files are read from the operating system. A file updated in
place or replaced is indexed again the next time a rule needs it; compile the
rules again to pick up new data, which reuses everything compiled from files
that did not change. `GeoData.LoadIP`, `LoadSite` and `Codes` read the files
directly, for example to list the categories a geosite file offers.

### Parsed rules

`ParseRule` checks a rule without reading any geodata, for example to
validate configuration input, and returns it in a normal form whose `String`
is the canonical spelling. `CompileRules` compiles parsed or built rules, and
`Matcher.Rules` and `MatchRule` return the rules of a `Matcher`:

```go
func validate(lines []string) error {
	for i, line := range lines {
		if geomatch.IsComment(line) {
			continue
		}
		if _, err := geomatch.ParseRule(line); err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return nil
}
```

## Rules

| Rule                                    | Matches                                                       |
|-----------------------------------------|---------------------------------------------------------------|
| `192.0.2.1`, `[2001:db8::1]:443`        | the address                                                   |
| `10.0.0.0/8`, `2001:db8::/32`           | the CIDR prefix                                               |
| `10.*`, `192.168.*.*`                   | IPv4 addresses with those leading octets                      |
| `geoip:cn`                              | an entry of `GeoData.IPFile`                                  |
| `geoip:!cn`                             | every address outside that entry                              |
| `geoip:private`                         | private and special-use ranges, built in if the file lacks it |
| `ext-ip:file.dat:code`                  | an entry of another geoip file                                |
| `full:example.com`                      | exactly `example.com`                                         |
| `domain:example.com`, `*example.com`    | `example.com` and its subdomains                              |
| `*.example.com`                         | the subdomains of `example.com` only                          |
| `keyword:ads`, `ads`                    | hosts containing the text                                     |
| `regexp:^ads?\.`                        | hosts matching the regular expression, case-insensitively     |
| `dotless:`, `dotless:intra`             | hosts without a dot, or those of them containing the text     |
| `geosite:google`                        | an entry of `GeoData.SiteFile`                                |
| `geosite:google@cn@ads`                 | its domains having every listed attribute                     |
| `ext-domain:file.dat:code`              | an entry of another geosite file                              |
| `ext:file.dat:code`                     | an entry of either kind, told apart by the file's contents    |

Rule kinds and codes are case-insensitive, a full-width colon (`：`) is read as
a colon, hosts may be written as URLs or `host:port`, and lines starting with
`#` or `;` are comments. Relative file names of `ext` rules are looked up in
`GeoData.Dir`, or next to `SiteFile` or `IPFile`. IP rules never match domain
names and domain rules never match IP addresses; IPv4-mapped IPv6 addresses
match as IPv4. `regexp:` matches regardless of case, and `dotless:` takes
plain text.
