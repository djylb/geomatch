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

// RefreshLives checks the files that g has read, as Check does, and
// refreshes, as Live.Refresh does, every Live compiled with g whose files may
// have changed since it last compiled or checked them, so that a program with
// many Lives, such as one per user, checks each file once rather than once
// per Live. report, if not nil, is called with each Live whose Refresh
// replaced its Matcher or failed. RefreshLives returns how many it replaced.
func (g *GeoData) RefreshLives(report func(l *Live, replaced bool, err error)) int {
	if g == nil {
		return 0
	}
	gen := g.Check()
	g.lives.mu.Lock()
	lives := g.lives.compactLocked()
	g.lives.mu.Unlock()
	n := 0
	for _, l := range lives {
		if l.seen.Load() == gen {
			continue
		}
		replaced, err := l.Refresh()
		if replaced {
			n++
		}
		if report != nil && (replaced || err != nil) {
			report(l, replaced, err)
		}
	}
	return n
}

// WatchLives calls RefreshLives every interval until ctx is done, with
// report. It returns ctx.Err(), or an error at once if interval is not
// positive. Run it in its own goroutine, once for the GeoData of the
// program:
//
//	go geo.WatchLives(ctx, time.Minute, func(l *geomatch.Live, replaced bool, err error) {
//		if err != nil {
//			log.Printf("geodata: %v", err)
//		}
//	})
func (g *GeoData) WatchLives(ctx context.Context, interval time.Duration, report func(l *Live, replaced bool, err error)) error {
	if interval <= 0 {
		return errors.New("geomatch: WatchLives interval must be positive")
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			g.RefreshLives(report)
		}
	}
}
