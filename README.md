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

Rules are written as common routing rule lists write them, so such lists
work as they are. Mind that a domain written without a kind, such as
`example.com`, is a keyword: it matches every host that contains the text,
`notexample.com` and `example.com.evil.net` too. Write `domain:example.com`
for the domain and its subdomains, or set `Compiler.PlainDomain` for rules
that your users write; see [Restricting rules](#restricting-rules).

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
`Match` uses from an address or URL, ending it at a backslash as browsers do.
Names are matched in their ASCII form, as TLS, DNS and geosite files hold
them: internationalized names in queries, in the domains of `full:`, `domain:`
and `*` rules, and in the full and domain entries of geosite files, are
converted to their `xn--` form, with full-width dots read as dots; `keyword:`,
`regexp:` and `dotless:` rules are text that must be ASCII. A host in the
legacy forms of IPv4 that system resolvers accept, such as `127.1`,
`2130706433` or `0x7f.0.0.1`, is matched as the address it stands for, so that
a denylist of addresses cannot be passed by spelling one differently.

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

`Allow` and `Deny` take any `MatcherSource`: a `*Matcher`, a `*Live`, an
`*IPSet`, a set of prefixes that changes while it is used, such as the
addresses that clients register at run time, or a type of your own whose
`Matcher` method returns the current rules.

`HasIPRules` and `HasDomainRules`, on a `Policy`, `Levels` or `Matcher`,
tell whether rules of that kind exist, so that a program resolves a host's
address for `AllowsHostIP` only when an IP rule could change the answer:

```go
ip := netip.Addr{}
if levels.HasIPRules() {
	ip = resolve(host)
}
allowed := levels.AllowsHostIP(host, ip)
```

So a denylist with exceptions is `Deny` and `Allow` with `AllowFirst`, and an
allowlist with exceptions `Allow` and `Deny` with `DenyFirst`. Only a nil
list is not set: leave the list nil when configuration has none. Any
`Matcher` is a set list, also one whose rules were all skipped, rejected or
filtered out by `ParseRules`, so that an allowlist of rules that fail allows
nothing. Either list may be a `Live`, which the policy follows as geodata
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

func (acl ACL) Policy() (geomatch.Policy, error) {
	m, err := compiler.CompileRules(acl.Rules)
	// Even with err, m holds the rules that compiled, and an allowlist of
	// none allows nothing.
	return acl.Mode.Policy(m), err
}

type Lists struct {
	Allow    []geomatch.Rule   `json:"allow"`
	Deny     []geomatch.Rule   `json:"deny"`
	Priority geomatch.Priority `json:"priority"` // "deny-first" (default) or "allow-first"
}

func (l Lists) Policy() (geomatch.Policy, error) {
	p := geomatch.Policy{Priority: l.Priority}
	var errs []error
	if l.Allow != nil { // a list that configuration lacks stays nil
		m, err := compiler.CompileRules(l.Allow)
		p.Allow, errs = m, append(errs, err)
	}
	if l.Deny != nil {
		m, err := compiler.CompileRules(l.Deny)
		p.Deny, errs = m, append(errs, err)
	}
	return p, errors.Join(errs...)
}
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
  A level's `Allow` then allows what it matches and leaves the rest to the
  next levels rather than denying it: a user level of `Allow: full:a.com`
  does not deny `b.com`.

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
that grows when one changed. `GeoData.LoadIP`, `LoadSite`, `IPCodes`,
`SiteCodes` and `SiteAttrs` read the files directly, for example to list the
categories and attributes a geosite file offers; they name files as `ext:`
rules do.

### Updating geodata while running

A `Live` holds rules and their `Matcher`, and compiles them again when their
geodata files change, so that a running program picks up new data without
restarting. Queries take the current `Matcher` without locking, and a new one
replaces it whole, so no query mixes old and new data:

```go
live, err := geomatch.NewLive(compiler, rules)
if err != nil {
	log.Print(err) // rules skipped; live holds the others
}
go live.Watch(ctx, time.Minute, func(replaced bool, err error) {
	log.Printf("geodata reloaded: %v, %v", replaced, err)
})

live.Matcher().Match(addr)

// A Policy over a Live follows its Matcher by itself.
p := geomatch.ModeAllowlist.Policy(live)
p.Allows(addr)
```

`Refresh` checks once, for programs that know when files change, and
`Update` replaces the rules; `NewLiveRules` and `UpdateRules` take parsed
rules. A program with many `Live`s on one `GeoData`, such as one for each
user, refreshes them all with one goroutine, which looks at each file once
per round and recompiles only the `Live`s whose files changed; a `Live` the
program drops leaves it by itself. `Live.SetTag` names a `Live` for the
report, and each broken file is reported once however many `Live`s it
broke:

```go
go geo.WatchLives(ctx, time.Minute, func(r geomatch.RefreshResult) {
	for _, err := range r.Errors {
		log.Printf("geodata: %v (kept the rules of %d lists)", err, len(r.Failed))
	}
})
```

If new geodata breaks a rule that compiled before, such as a file removed or
replaced by a broken one, `Live` keeps the previous `Matcher` and reports the
error, which `Live.RefreshErr` returns for health checks, and tries again
once the files change. Replace a file by renaming a
new one over it rather than writing it in place, so that no compile reads it
half written.

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
contain it, as rule lists usually mean it. That is the widest reading, so
`PlainDomain` can make it `domain:` (the domain and its subdomains) or
`full:` instead. Note that `*example.com` is `domain:example.com`, the domain
and its subdomains, not any name that ends in the text:

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
// validate checks rules that users write against the restrictions of
// users, the Compiler that will compile them.
func validate(text string) error {
	_, err := users.ParseRules(geomatch.SplitLines(text))
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
uses `encoding.TextUnmarshaler`; the `Compiler`'s restrictions and
`PlainDomain` apply when `CompileRules` compiles them, as a domain written
without a kind stays so (`Rule.Plain`).

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
match domain names and domain rules never match IP addresses; IPv4-mapped
IPv6 addresses match as IPv4. `regexp:` matches regardless of case,
`dotless:` takes plain text without a dot, and an attribute after `@` must
not be empty. Domains of `full:`, `domain:` and `*` rules may be written as
internationalized names, which are converted to their `xn--` form; rules that
no host could match are invalid rather than silently dead: non-ASCII
`keyword:`, `regexp:` and `dotless:` text, and domains that are IPv4
addresses in a legacy form, such as `127.1`, which queries read as
addresses.
