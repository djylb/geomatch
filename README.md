# geomatch

Match IP addresses and domain names against routing rules, including
`geoip:` and `geosite:` rules backed by `geoip.dat` and `geosite.dat` files,
for access control and traffic routing in Go.

- No dependencies beyond the standard library, and builds on every Go port.
- Rules compile into an immutable `Matcher` safe for concurrent use; queries
  of lowercase hosts do not allocate.
- Geodata files are indexed on first use, so a rule reads only its own entry
  of a file of tens of megabytes, and files changed on disk are picked up.

## Install

```bash
go get github.com/djylb/geomatch
```

## Usage

```go
func newMatcher() (*geomatch.Matcher, error) {
	geo := &geomatch.GeoData{IPFile: "conf/geoip.dat", SiteFile: "conf/geosite.dat"}
	m, err := geomatch.Compile([]string{
		"geoip:cn",
		"geosite:cn",
		"10.0.0.0/8",
		"domain:example.com",
	}, geomatch.Options{GeoData: geo})
	if err != nil {
		// Invalid rules, or rules whose geodata could not be read, were
		// skipped; m holds the others.
		log.Print(err)
	}
	return m, nil
}

func route(m *geomatch.Matcher, target string) string {
	if m.Match(target) { // "www.example.com:443", "10.1.2.3", "https://host/path"
		return "direct"
	}
	return "proxy"
}
```

A `Policy` turns a `Matcher` into an allowlist or a denylist:

```go
func allowClient(rules *geomatch.Matcher, remote net.Addr) bool {
	p := geomatch.Policy{Mode: geomatch.Allowlist, Rules: rules}
	return p.Allows(remote.String())
}
```

`SplitRules` splits a multi-line configuration value into rules. `HostOf`
extracts the host that `Match` uses from an address or URL. `MatchIP` takes a
`netip.Addr` without any parsing, and `MatchDomain` a host name, also as
`host:port`, that is never treated as an IP address.

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
match as IPv4.

`GeoData.LoadIP`, `LoadSite` and `Codes` read the files directly, at the paths
given, for example to list the categories a geosite file offers. A file
replaced on disk is indexed again on the next lookup.

Notes on the rules:

- `regexp:` matches case-insensitively.
- `dotless:` takes plain text, not a regular expression fragment.
- `geoip:private` works without a geoip file.
- `ext:` accepts either kind of file; `ext-ip:` and `ext-domain:` name the kind.

## Performance

Medians on an Apple M5 Pro (`go test -bench .`, with geoip.dat and
geosite.dat files named by `GEOMATCH_GEOIP` and `GEOMATCH_GEOSITE`):

| Query                                                | Time   |
|------------------------------------------------------|--------|
| `MatchIP` against 10,000 prefixes                    | 25 ns  |
| `MatchIP` against `geoip:cn`                         | 21 ns  |
| `MatchDomain` missing 50,000 `domain:` rules         | 138 ns |
| `MatchDomain` missing `geosite:cn` (119,000 domains) | 131 ns |
| `Match("www.example.com:443")`, parsing included     | 61 ns  |

Addresses are kept as merged ranges searched in binary, domains as a map per
label of the host, and keywords together with the literal text that each
regular expression requires in one Aho-Corasick automaton, so only the
regular expressions whose text occurs in the host run. Compiling `geoip:cn`
and `geosite:cn` from the files takes about 15–20 ms.
