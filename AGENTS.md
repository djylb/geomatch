# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass. Run the real-data tests too when the files are at hand:
  set `GEOMATCH_GEOIP` and `GEOMATCH_GEOSITE` to a geoip.dat and a
  geosite.dat.
- Standard library only, also for tests.
- Queries (`Match*`, `Allows*`, `Find*`, `Decide*`, `Route*`) of IP
  addresses and ASCII host names stay allocation-free and take no lock.
- Rules mean what common routing rule lists mean: a plain domain is a
  keyword. `Find` and `Decide` must name the first rule that `Match` would
  match.
- Fail closed: only a nil list means "not set"; a list whose rules were all
  filtered out matches nothing, and an allowlist of nothing allows nothing.
- Rules, queries and geosite values are normalised the same way: lowercase,
  full-width dots as dots, internationalized labels in their xn-- form.
- Treat geodata files and rule text as untrusted: bound every read and every
  parse.
- Tests must not leak goroutines or timers.
- The README, docs and commits name no other project and quote no benchmark
  numbers.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
