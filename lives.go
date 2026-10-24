package geomatch

import (
	"context"
	"errors"
	"sync"
	"time"
	"weak"
)

// liveList holds the Lives compiled with a GeoData, weakly, so that a Live
// the program no longer uses goes without being removed.
type liveList struct {
	mu    sync.Mutex
	lives []weak.Pointer[Live]
	limit int // length at which add drops the Lives gone, to bound the list
}

func (g *GeoData) addLive(l *Live) {
	ll := &g.lives
	ll.mu.Lock()
	defer ll.mu.Unlock()
	if len(ll.lives) >= ll.limit {
		ll.compactLocked()
		ll.limit = max(64, 2*len(ll.lives))
	}
	ll.lives = append(ll.lives, weak.Make(l))
}

// compactLocked drops the Lives gone and returns the others.
func (ll *liveList) compactLocked() []*Live {
	var lives []*Live
	kept := ll.lives[:0]
	for _, w := range ll.lives {
		if l := w.Value(); l != nil {
			lives = append(lives, l)
			kept = append(kept, w)
		}
	}
	clear(ll.lives[len(kept):])
	ll.lives = kept
	return lives
}

// RefreshResult reports a round of GeoData.RefreshLives.
type RefreshResult struct {
	// Replaced are the Lives whose Matcher was compiled again.
	Replaced []*Live
	// Failed are the Lives that kept their Matcher because new geodata broke
	// rules that compiled before, as their RefreshErr reports.
	Failed []*Live
	// Errors are the distinct geodata errors of the Failed Lives, one per
	// file and cause however many Lives it broke, for a log.
	Errors []error
}

// Changed reports whether the round replaced or kept a Matcher.
func (r RefreshResult) Changed() bool {
	return len(r.Replaced) > 0 || len(r.Failed) > 0
}

// RefreshLives checks the files that g has read, as Check does, and
// refreshes, as Live.Refresh does, every Live compiled with g whose files may
// have changed since it last compiled or checked them, so that a program with
// many Lives, such as one per user, checks each file once rather than once
// per Live: a Live compares its files with the versions that Check saw, and
// looks again only at those that changed, did not exist or could not be
// read. Live.Tag tells the Lives of the result apart.
func (g *GeoData) RefreshLives() RefreshResult {
	var res RefreshResult
	if g == nil {
		return res
	}
	gen := g.Check()
	g.lives.mu.Lock()
	lives := g.lives.compactLocked()
	g.lives.mu.Unlock()
	seen := make(map[string]bool)
	for _, l := range lives {
		if !l.due(gen) {
			continue
		}
		switch replaced, err := l.refresh(true); {
		case replaced:
			res.Replaced = append(res.Replaced, l)
		case err != nil:
			res.Failed = append(res.Failed, l)
			for _, e := range geoCauses(err) {
				if msg := e.Error(); !seen[msg] {
					seen[msg] = true
					res.Errors = append(res.Errors, e)
				}
			}
		}
	}
	return res
}

// geoCauses returns the geodata errors of err, without the rules they broke.
func geoCauses(err error) []error {
	var errs RuleErrors
	if !errors.As(err, &errs) {
		return []error{err}
	}
	var causes []error
	for _, e := range errs.Filter(ErrGeoData) {
		causes = append(causes, e.Err)
	}
	return causes
}

// WatchLives calls RefreshLives every interval until ctx is done, and
// report, if not nil, with each result that Changed. It returns ctx.Err(),
// or an error at once if interval is not positive. Run it in its own
// goroutine, once for the GeoData of the program:
//
//	go geo.WatchLives(ctx, time.Minute, func(r geomatch.RefreshResult) {
//		for _, err := range r.Errors {
//			log.Printf("geodata: %v (kept the rules of %d lists)", err, len(r.Failed))
//		}
//	})
func (g *GeoData) WatchLives(ctx context.Context, interval time.Duration, report func(RefreshResult)) error {
	return every(ctx, interval, "WatchLives", func() {
		if res := g.RefreshLives(); report != nil && res.Changed() {
			report(res)
		}
	})
}
