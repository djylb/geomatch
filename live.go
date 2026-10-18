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
// changed, or run Watch.
//
// Replace a geodata file by renaming a new file over it rather than by
// writing it in place, so that a compile never reads a file half written
// and the change is seen even if size and time stay the same.
//
// The methods are safe for concurrent use.
type Live struct {
	compiler Compiler

	mu    sync.Mutex // serializes compiles
	rules []string
	err   error    // of the current Matcher's compile
	tried *Matcher // the sources of a compile that Refresh rejected, for Stale

	cur atomic.Pointer[Matcher]
}

// NewLive compiles rules with c, as c.Compile does: the error lists the
// rules skipped, and the Live holds the others.
func NewLive(c Compiler, rules []string) (*Live, error) {
	l := &Live{compiler: c, rules: slices.Clone(rules)}
	m, err := c.Compile(l.rules)
	l.cur.Store(m)
	l.err = err
	return l, err
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

// Rules returns the rules that the Live compiles.
func (l *Live) Rules() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.rules)
}

// Update replaces the rules and compiles them, replacing the Matcher even if
// rules are skipped, which the error lists as Compile's does.
func (l *Live) Update(rules []string) error {
	rules = slices.Clone(rules)
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.compiler.Compile(rules)
	l.rules, l.err, l.tried = rules, err, nil
	l.cur.Store(m)
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
	check := l.cur.Load()
	if l.tried != nil {
		check = l.tried
	}
	if !check.Stale() {
		return false, nil
	}
	m, err := l.compiler.Compile(l.rules)
	if newGeoFailure(err, l.err) {
		l.tried = &Matcher{geo: m.geo, sources: m.sources} // not its rules
		return false, err
	}
	l.err, l.tried = err, nil
	l.cur.Store(m)
	return true, err
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
