package geomatch

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Live holds rules and the Matcher compiled from them, and compiles them
// again when their geodata files change or the rules do, so that a running
// program picks up new geodata. Queries take the current Matcher without
// locking; a new one replaces it whole, so no query sees a mix of old and
// new data. Live starts no goroutines: call Refresh when the files may have
// changed, or run Watch; a program with many Lives on one GeoData refreshes
// them all with GeoData.RefreshLives or GeoData.WatchLives.
//
// Replace a geodata file by renaming a new file over it rather than by
// writing it in place, so that a compile never reads a file half written
// and the change is seen even if size and time stay the same.
//
// The methods are safe for concurrent use.
type Live struct {
	compiler Compiler

	mu sync.Mutex // serializes compiles
	// rules are compiled with Compile, or parsed, when byRule is set, with
	// CompileRules.
	rules  []string
	parsed []Rule
	byRule bool
	err    error    // of the current Matcher's compile
	tried  *Matcher // the sources of a compile that Refresh rejected, for Stale
	failed error    // of the last Refresh, which kept the Matcher, or nil
	tag    any      // of SetTag

	cur atomic.Pointer[Matcher]
	// seen is the generation of the compiler's GeoData when the Live last
	// compiled or checked its files, so that GeoData.RefreshLives skips it
	// while no file changed.
	seen atomic.Uint64
}

// NewLive compiles rules with c, as c.Compile does: the error lists the
// rules skipped, and the Live holds the others.
func NewLive(c Compiler, rules []string) (*Live, error) {
	return newLive(&Live{compiler: c, rules: slices.Clone(rules)})
}

// NewLiveRules is NewLive for parsed or built rules, which it compiles as
// c.CompileRules does.
func NewLiveRules(c Compiler, rules []Rule) (*Live, error) {
	return newLive(&Live{compiler: c, parsed: cloneRules(rules), byRule: true})
}

func newLive(l *Live) (*Live, error) {
	gen := l.generation()
	m, err := l.compile()
	l.cur.Store(m)
	l.err = err
	l.seen.Store(l.seenAfter(gen))
	if g := l.compiler.GeoData; g != nil {
		g.addLive(l)
	}
	return l, err
}

// compile compiles the rules of l.
func (l *Live) compile() (*Matcher, error) {
	if l.byRule {
		return l.compiler.CompileRules(l.parsed)
	}
	return l.compiler.Compile(l.rules)
}

// generation returns the generation of the compiler's GeoData.
func (l *Live) generation() uint64 {
	return l.compiler.GeoData.Generation()
}

// unseen is a seen that no generation equals.
const unseen = ^uint64(0)

// seenAfter returns what seen records after a compile or check that started
// at generation gen: gen, or unseen while a rule failed on geodata or a file
// was missing, since GeoData.Check may not watch such files, so that
// RefreshLives refreshes the Live every time, as Refresh would see the fix.
func (l *Live) seenAfter(gen uint64) uint64 {
	if l.tried != nil || errors.Is(l.err, ErrGeoData) || l.cur.Load().missingSource() {
		return unseen
	}
	return gen
}

// cloneRules copies rules with their attributes.
func cloneRules(rules []Rule) []Rule {
	out := slices.Clone(rules)
	for i := range out {
		out[i].Attrs = slices.Clone(out[i].Attrs)
	}
	return out
}

// Matcher returns the current Matcher, for queries, such as
// live.Matcher().Match(addr). Take it once for queries that belong together.
// A Policy or Router given the Live follows it by itself:
//
//	p := geomatch.Policy{Allow: live}
func (l *Live) Matcher() *Matcher {
	if l == nil {
		return nil
	}
	return l.cur.Load()
}

// Err returns the error of the compile that gave the current Matcher: the
// rules it skipped, or nil.
func (l *Live) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Rules returns the rules that the Live compiles; rules given as Rule values
// in the spelling of Rule.String.
func (l *Live) Rules() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byRule {
		out := make([]string, len(l.parsed))
		for i, r := range l.parsed {
			out[i] = r.String()
		}
		return out
	}
	return slices.Clone(l.rules)
}

// Update replaces the rules and compiles them, replacing the Matcher even if
// rules are skipped, which the error lists as Compile's does.
func (l *Live) Update(rules []string) error {
	rules = slices.Clone(rules)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules, l.parsed, l.byRule = rules, nil, false
	return l.recompileLocked()
}

// UpdateRules is Update for parsed or built rules, which it compiles as
// Compiler.CompileRules does.
func (l *Live) UpdateRules(rules []Rule) error {
	rules = cloneRules(rules)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules, l.parsed, l.byRule = nil, rules, true
	return l.recompileLocked()
}

func (l *Live) recompileLocked() error {
	gen := l.generation()
	m, err := l.compile()
	l.err, l.tried, l.failed = err, nil, nil
	l.cur.Store(m)
	l.seen.Store(l.seenAfter(gen))
	return err
}

// Refresh compiles the rules again if a geodata file that the current
// Matcher was compiled from has changed, and reports whether it replaced
// the Matcher. It checks the files' metadata only, so it is cheap to call
// often.
//
// A rule that compiled before but whose new geodata cannot be read, such as
// a file removed or replaced by a broken one, keeps the current Matcher:
// Refresh returns false and the error of the new compile, and compiles again
// once the files change again. Otherwise the error is that of the new
// compile, as Err returns it, or nil.
func (l *Live) Refresh() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The generation before the check: a change after it grows it again.
	gen := l.generation()
	defer func() { l.seen.Store(l.seenAfter(gen)) }()
	check := l.cur.Load()
	if l.tried != nil {
		check = l.tried
	}
	if !check.Stale() {
		return false, nil
	}
	m, err := l.compile()
	if newGeoFailure(err, l.err) {
		l.tried = &Matcher{geo: m.geo, cfgGen: m.cfgGen, sources: m.sources} // not its rules
		l.failed = err
		return false, err
	}
	l.err, l.tried, l.failed = err, nil, nil
	l.cur.Store(m)
	return true, err
}

// RefreshErr returns the error of the last Refresh, or GeoData.RefreshLives,
// that kept the current Matcher because new geodata broke a rule that
// compiled before, such as a file replaced by a broken one; or nil once the
// Matcher follows the files again. Err, of the current Matcher, does not
// report it, so health checks should look at both.
func (l *Live) RefreshErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}

// SetTag attaches v to the Live, such as the user or the list it holds the
// rules of, for reports of GeoData.RefreshLives; a map from Lives to such
// values would keep the Lives that the program dropped.
func (l *Live) SetTag(v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tag = v
}

// Tag returns the value of SetTag, or nil.
func (l *Live) Tag() any {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tag
}

// newGeoFailure reports whether err has a geodata failure of a rule that
// did not fail in prev.
func newGeoFailure(err, prev error) bool {
	var errs, before RuleErrors
	if !errors.As(err, &errs) {
		return false
	}
	errors.As(prev, &before)
	for _, e := range errs.Filter(ErrGeoData) {
		if !slices.ContainsFunc(before, func(b *RuleError) bool { return b.Index == e.Index }) {
			return true
		}
	}
	return false
}

// Watch calls Refresh every interval until ctx is done, and report, if not
// nil, with the result of each Refresh that replaced the Matcher or failed.
// It returns ctx.Err(), or an error at once if interval is not positive.
// Run it in its own goroutine:
//
//	go live.Watch(ctx, time.Minute, func(replaced bool, err error) {
//		if err != nil {
//			log.Printf("geodata: replaced=%v: %v", replaced, err)
//		}
//	})
func (l *Live) Watch(ctx context.Context, interval time.Duration, report func(replaced bool, err error)) error {
	if interval <= 0 {
		return errors.New("geomatch: Watch interval must be positive")
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			replaced, err := l.Refresh()
			if report != nil && (replaced || err != nil) {
				report(replaced, err)
			}
		}
	}
}
