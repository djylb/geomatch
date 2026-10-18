# geomatch

Match IP addresses and domain names against routing rules, including
`geoip:` and `geosite:` rules backed by `geoip.dat` and `geosite.dat` files,
for access control and traffic routing in Go.

- No dependencies beyond the standard library, and builds on every Go port.
- Rules compile into a `Matcher` safe for concurrent use; queries of lowercase
  hosts do not allocate.
- Geodata files are indexed on first use, so a rule reads only its own entry
  of a file of tens of megabytes, and a `Live` picks up files updated while
  the program runs.
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
var compiler = geomatch.Compiler{
	GeoData: geomatch.NewGeoData(geomatch.GeoFiles{IP: "geoip.dat", Site: "geosite.dat"}),
}

func newMatcher() *geomatch.Matcher {
	m, err := compiler.Compile([]string{
		"geoip:cn",
		"geosite:cn",
		"10.0.0.0/8",
		"domain:example.com",
	})
	if err != nil {
		// Invalid rules, or rules whose geodata could not be read, were
		// skipped; m holds the others. err is a geomatch.RuleErrors with
		// the index of each.
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

`geomatch.Compile` compiles rules without geodata, and `MustCompile` panics
on an invalid rule, for rules fixed in a program.

Every query comes in five forms, by what the caller holds. `Levels` have the
methods of `Policy`, and a `Router` has `Route…` and, with the rule, `Find…`
in the same forms:

| Input                                   | `Matcher`      | `Matcher`, with the rule | `Policy`        | `Policy`, with the rule |
|-----------------------------------------|----------------|--------------------------|-----------------|-------------------------|
| address, `host:port` or URL (`string`)  | `Match`        | `Find`                   | `Allows`        | `Decide`                |
| `netip.Addr`                            | `MatchIP`      | `FindIP`                 | `AllowsIP`      | `DecideIP`              |
| domain name, never read as an IP        | `MatchDomain`  | `FindDomain`             | `AllowsDomain`  | `DecideDomain`          |
| `net.Addr`, such as a `RemoteAddr`      | `MatchNetAddr` | `FindNetAddr`            | `AllowsNetAddr` | `DecideNetAddr`         |
| domain name and the IP it resolved to   | `MatchHostIP`  | `FindHostIP`             | `AllowsHostIP`  | `DecideHostIP`          |

`net.Addr` values are matched without formatting them. `MatchHostIP` matches
if either the name or the address does, so that an allowlist of `geoip:`
rules allows a host by where it resolves. `HostOf` extracts the host that
`Match` uses from an address or URL. Hosts and rules are ASCII: write
internationalized names in their `xn--` form, as geosite files do.

### Allowing and denying

A `Policy` allows or denies addresses by an allowlist, a denylist, or both.
`Decide` also reports the rule that decided, and a `Decision` prints as
`denied by geoip:cn`, for logs:

```go
denylist := geomatch.Policy{Deny: blocked}
allowlist := geomatch.Policy{Allow: trusted}
denyWins := geomatch.Policy{Allow: trusted, Deny: blocked}
allowWins := geomatch.Policy{Allow: exceptions, Deny: blocked, Priority: geomatch.AllowFirst}

if d := denylist.DecideNetAddr(conn.RemoteAddr()); !d.Allowed {
	log.Printf("%v %v", conn.RemoteAddr(), d) // "192.0.2.7:51234 denied by geoip:cn"
}
```

| Lists                     | only on Allow | only on Deny | on both | on neither |
|---------------------------|---------------|--------------|---------|------------|
| `Allow`                   | allowed       |              |         | denied     |
| `Deny`                    |               | denied       |         | allowed    |
| both, `DenyFirst` (zero)  | allowed       | denied       | denied  | denied     |
| both, `AllowFirst`        | allowed       | denied       | allowed | allowed    |
| neither (zero `Policy`)   |               |              |         | allowed    |

So a denylist with exceptions is `Deny` and `Allow` with `AllowFirst`, and an
allowlist with exceptions `Allow` and `Deny` with `DenyFirst`. A list that is
nil or compiled from no rules is not set, so compiling every list of a
configuration is enough; a list whose rules were all skipped, such as for
missing geodata, is set and matches nothing, so that an allowlist fails
closed. Either list may be a `Live`, which the policy follows as geodata
changes.

`Mode` (`ModeOff`, `ModeAllowlist`, `ModeDenylist`) and `Priority`
(`DenyFirst`, `AllowFirst`) read and write their names in configuration
files, as `Rule` does its text. `Mode` also reads `whitelist`, `blacklist`,
`allow`, `deny` and the numbers `0` to `2`, and `Mode.Policy` makes the
policy of a mode and its rules, an allowlist without rules allowing nothing:

```go
type ACL struct {
	Mode  geomatch.Mode   `json:"mode"`  // "allowlist", "denylist" or "off"
	Rules []geomatch.Rule `json:"rules"` // ["geoip:cn", "domain:example.com"]
}
m, err := compiler.CompileRules(acl.Rules)
p := acl.Mode.Policy(m)

type Lists struct {
	Allow    []geomatch.Rule   `json:"allow"`
	Deny     []geomatch.Rule   `json:"deny"`
	Priority geomatch.Priority `json:"priority"` // "deny-first" (default) or "allow-first"
}
allow, _ := compiler.CompileRules(lists.Allow)
deny, _ := compiler.CompileRules(lists.Deny)
p := geomatch.Policy{Allow: allow, Deny: deny, Priority: lists.Priority}
```

### Levels

`Levels` apply policies of several levels, such as global, per-user,
per-client and per-resource ones, in one of two ways:

- By default every level must allow, so a level can only narrow what those
  before it allow: an administrator's global denylist binds every user.
- With `FirstMatch` the first level whose rules match decides, overriding the
  levels after it either way. List the levels most authoritative first, or
  most specific first for settings that override general ones. Addresses
  that no level's rules match are allowed, or denied with `DenyUnmatched`.

A level that is not set, the zero `Policy`, changes nothing either way.
`Decision.Level` tells which level decided, and a `Policy` with a `Name`
names itself in its `Decision` and the `Decision`'s text:

```go
user := geomatch.Policy{Name: "user 7", Deny: userRules}
levels := geomatch.Levels{Policies: []geomatch.Policy{global, user, client, tunnel}}
if d := levels.DecideNetAddr(conn.RemoteAddr()); !d.Allowed {
	log.Printf("%v %v", conn.RemoteAddr(), d) // "192.0.2.7:51234 denied by geoip:cn (user 7)"
}
```

### Routing

A `Router` maps addresses to targets by ordered routes: the first route that
matches decides, and `Default` applies when none does. It routes traffic, and
with `bool` targets it is an access list in any order of priority:

```go
router := geomatch.Router[string]{
	Routes: []geomatch.Route[string]{
		{Matcher: ads, Target: "block"},
		{Matcher: china, Target: "direct"},
	},
	Default: "proxy",
}
outbound := router.Route(addr)
log.Print(router.Find(addr)) // "direct by geosite:cn (route 1)"
```

In short:

| Need                                                  | Use                                 |
|-------------------------------------------------------|-------------------------------------|
| an allowlist, a denylist, or both with exceptions     | `Policy`                            |
| levels that must all allow, later ones only narrowing | `Levels`                            |
| levels where the first whose rules match decides      | `Levels` with `FirstMatch`          |
| a target per address, or rules in any priority order  | `Router[T]`                         |
| any of these following geodata as it changes         | `Live` in place of a `Matcher`      |

### Geodata

```go
//go:embed geo/geoip.dat geo/geosite.dat
var geoFiles embed.FS

var geo = geomatch.NewGeoData(geomatch.GeoFiles{FS: geoFiles, IP: "geo/geoip.dat", Site: "geo/geosite.dat"})
```

Use one `GeoData` for the program, so that its compiled entries are shared.
Without `FS`, the files are read from the operating system. A file updated in
place or replaced is indexed again the next time a rule needs it; compile the
rules again to pick up new data, which reuses everything compiled from files
that did not change. `Matcher.Stale` reports when a file it was compiled
from changed or appeared, and `Matcher.Sources` lists those files.
`GeoData.SetFiles` changes the files while the program runs, such as when
configuration is reloaded; Matchers of the old files then report `Stale`.
`GeoData.Check` looks at every file it has read and returns a generation
that grows when one changed, so a program with many `Live`s refreshes them
only when it grew. `GeoData.LoadIP`, `LoadSite`, `IPCodes` and `SiteCodes`
read the files directly, for example to list the categories a geosite file
offers.

### Updating geodata while running

A `Live` holds rules and their `Matcher`, and compiles them again when their
geodata files change, so that a running program picks up new data without
restarting. Queries take the current `Matcher` without locking, and a new one
replaces it whole, so no query mixes old and new data:

```go
live, err := geomatch.NewLive(compiler, rules)
go live.Watch(ctx, time.Minute, func(replaced bool, err error) {
	log.Printf("geodata reloaded: %v, %v", replaced, err)
})

live.Matcher().Match(addr)

// A Policy over a Live follows its Matcher by itself.
p := geomatch.Policy{Mode: geomatch.ModeAllowlist, Matcher: live}
p.Allows(addr)
```

`Refresh` checks once, for programs that know when files change, and
`Update` replaces the rules. If new geodata breaks a rule that compiled
before, such as a file removed or replaced by a broken one, `Live` keeps the
previous `Matcher` and reports the error, and tries again once the files
change. Replace a file by renaming a new one over it rather than writing it in
place, so that no compile reads it half written.

### Restricting rules

A `Compiler` can restrict the rules it accepts, for example for rules that
untrusted users write. The zero `Compiler` accepts every rule, without
limits. Common settings:

```go
// Rules about client addresses: domain rules could never match them.
clients := geomatch.Compiler{GeoData: geo, Kinds: geomatch.IPKinds}

// Rules that users write: no regular expressions, geodata files only from
// the geodata directory, and bounded in number and size.
users := geomatch.Compiler{
	GeoData:  geo,
	Kinds:    geomatch.AllKinds.Without(geomatch.RuleRegexp),
	ExtFiles: geomatch.ExtLocal, // ext: names within the geodata directory; ExtNone disables ext:
	Limits:   geomatch.Limits{MaxRules: 1000, MaxRuleLen: 256},
}

// A program without geodata, which should refuse geo rules up front rather
// than skip them when compiling.
plain := geomatch.Compiler{Kinds: geomatch.AllKinds &^ geomatch.GeoKinds}
```

`IPKinds`, `DomainKinds`, `GeoKinds` and `AllKinds` are sets of the kinds in
the [rules table](#rules); `KindsOf` builds others. Restricted rules are
invalid: `ParseRules` rejects them as `Compile` does, so validating
configuration catches them. Every skipped rule's error is an
`ErrInvalidRule`, a fault of the rule, or an `ErrGeoData`, a fault of the
geodata at hand, such as a missing file; `RuleErrors.Filter` picks either.
A rule of a kind left out fails with a `*KindError`, which holds the kind
read and the kinds allowed, and says so: `keyword rules are not allowed here
(allowed: ip, geoip)`.

A domain written without a kind, such as `example.com`, matches hosts that
contain it, as V2Ray reads it. That is the widest reading, so `PlainDomain`
can make it `domain:` (the domain and its subdomains) or `full:` instead:

```go
users.PlainDomain = geomatch.RuleDomain // "example.com" is domain:example.com
```

A misspelt kind, such as `ful:example.com`, and an IP range, such as
`1.1.1.1-1.1.1.5`, are invalid rather than read as keywords.

### Parsed rules

`ParseRule` and `ParseRules`, or those of a `Compiler`, check rules without
reading any geodata, for example to validate configuration input, and return
them in a normal form whose `String` is the canonical spelling.
`Normalize` returns them as canonical text without duplicates, to save.
`CompileRules` compiles parsed or built rules, and `Matcher.Rules` returns
the rules of a `Matcher`. `ParseRule` fails with a `*RuleError`, and
`ParseRules` with a `RuleErrors` of them:

```go
func validate(text string) error {
	_, err := geomatch.ParseRules(geomatch.SplitLines(text))
	var errs geomatch.RuleErrors
	if errors.As(err, &errs) {
		e := errs[0]
		return fmt.Errorf("line %d: %q: %w", e.Index+1, e.Rule, e.Err)
	}
	return nil
}
```

`SplitLines` splits rule text, such as a file, into lines whose positions it
keeps, whether they end in `\n`, `\r\n` or `\r`, and drops a byte order
mark; rules are trimmed of spaces and a byte order mark however they were
split.

A `Rule` reads and writes itself as text, so configuration can hold
`[]geomatch.Rule`, checked as it is decoded, in JSON, YAML or any format that
uses `encoding.TextUnmarshaler`; the `Compiler`'s restrictions apply when
`CompileRules` compiles them.

## Rules

| Rule                                    | Matches                                                       | Kind            |
|-----------------------------------------|---------------------------------------------------------------|-----------------|
| `192.0.2.1`, `[2001:db8::1]:443`        | the address                                                   | `RuleIP`        |
| `10.0.0.0/8`, `2001:db8::/32`           | the CIDR prefix                                               | `RuleIP`        |
| `10.*`, `192.168.*.*`                   | IPv4 addresses with those leading octets                      | `RuleIP`        |
| `geoip:cn`                              | an entry of the geoip file, `GeoFiles.IP`                     | `RuleGeoIP`     |
| `geoip:!cn`                             | every address outside that entry                              | `RuleGeoIP`     |
| `geoip:private`                         | private and special-use ranges, built in if the file lacks it | `RuleGeoIP`     |
| `ext-ip:file.dat:code`                  | an entry of another geoip file                                | `RuleGeoIP`     |
| `full:example.com`                      | exactly `example.com`                                         | `RuleFull`      |
| `domain:example.com`, `*example.com`    | `example.com` and its subdomains                              | `RuleDomain`    |
| `*.example.com`                         | the subdomains of `example.com` only                          | `RuleSubdomain` |
| `keyword:ads`, `ads`                    | hosts containing the text (see `PlainDomain`)                 | `RuleKeyword`   |
| `regexp:^ads?\.`                        | hosts matching the regular expression, case-insensitively     | `RuleRegexp`    |
| `dotless:`, `dotless:intra`             | hosts without a dot, or those of them containing the text     | `RuleDotless`   |
| `geosite:google`                        | an entry of the geosite file, `GeoFiles.Site`                 | `RuleGeoSite`   |
| `geosite:google@cn@ads`                 | its domains having every listed attribute                     | `RuleGeoSite`   |
| `ext-domain:file.dat:code`              | an entry of another geosite file                              | `RuleGeoSite`   |
| `ext:file.dat:code`                     | an entry of either kind, told apart by the file's contents    | `RuleExt`       |

Rule kinds and codes are case-insensitive, a full-width colon (`：`) is read as
a colon, hosts may be written as URLs or `host:port`, and lines starting with
`#` or `;` are comments. Relative file names of `ext` rules are looked up in
`GeoFiles.Dir`, or next to the default file of the rule's kind, or the other
one, or in the root of `FS`, never in the working directory. IP rules never
match domain
names and domain rules never match IP addresses; IPv4-mapped IPv6 addresses
match as IPv4. `regexp:` matches regardless of case, and `dotless:` takes
plain text.
