package geomatch

import (
	"fmt"
	"net"
	"net/netip"
)

// Router maps addresses to targets by ordered routes: the first route whose
// rules match decides, and Default applies when none does, as in routing
// traffic to "direct", "proxy" or "block":
//
//	r := geomatch.Router[string]{
//		Routes: []geomatch.Route[string]{
//			{Matcher: ads, Target: "block"},
//			{Matcher: china, Target: "direct"},
//		},
//		Default: "proxy",
//	}
//
// Like those of Matcher, its methods come in five forms, by the kind of
// address. Route returns the target, and Find also which route and rule
// decided, at more cost when a route matches. A Router is safe for
// concurrent use while its fields are not changed.
type Router[T any] struct {
	Routes  []Route[T]
	Default T
}

// Route is a route of a Router: addresses that Matcher matches go to
// Target. Matcher may be a *Matcher, or a *Live that the route then follows
// as geodata changes; nil matches nothing.
type Route[T any] struct {
	Matcher MatcherSource
	Target  T
}

// Routed is the answer of a Router for an address, with the route and rule
// that decided.
type Routed[T any] struct {
	Target T
	// Matched reports whether a route matched; otherwise Target is the
	// Router's Default.
	Matched bool
	// Index is the position of the route in Routes, or -1 for the default.
	Index int
	// Rule is the first rule of the route that matched.
	Rule Rule
}

// String describes r for logs, as "proxy by geosite:google (route 2)" or
// "direct by default".
func (r Routed[T]) String() string {
	if !r.Matched {
		return fmt.Sprintf("%v by default", r.Target)
	}
	return fmt.Sprintf("%v by %v (route %d)", r.Target, r.Rule, r.Index)
}

// Route returns the target of addr, as Matcher.Match reads it.
func (r Router[T]) Route(addr string) T { return r.route(addrTarget(addr)) }

// RouteIP returns the target of ip.
func (r Router[T]) RouteIP(ip netip.Addr) T { return r.route(ipTarget(ip)) }

// RouteDomain returns the target of host, as Matcher.MatchDomain reads it.
func (r Router[T]) RouteDomain(host string) T { return r.route(domainTarget(host)) }

// RouteNetAddr returns the target of a, as Matcher.MatchNetAddr reads it.
func (r Router[T]) RouteNetAddr(a net.Addr) T { return r.route(netAddrTarget(a)) }

// RouteHostIP returns the target of a domain name and the IP address it
// resolved to, as Matcher.MatchHostIP reads them.
func (r Router[T]) RouteHostIP(host string, ip netip.Addr) T {
	return r.route(hostIPTarget(host, ip))
}

// Find is Route that also reports the route and rule that decided, for
// logging.
func (r Router[T]) Find(addr string) Routed[T] { return r.find(addrTarget(addr)) }

// FindIP is Find for an IP address.
func (r Router[T]) FindIP(ip netip.Addr) Routed[T] { return r.find(ipTarget(ip)) }

// FindDomain is Find for a domain name.
func (r Router[T]) FindDomain(host string) Routed[T] { return r.find(domainTarget(host)) }

// FindNetAddr is Find for a net.Addr.
func (r Router[T]) FindNetAddr(a net.Addr) Routed[T] { return r.find(netAddrTarget(a)) }

// FindHostIP is Find for a domain name and its IP address.
func (r Router[T]) FindHostIP(host string, ip netip.Addr) Routed[T] {
	return r.find(hostIPTarget(host, ip))
}

func (r Router[T]) route(t target) T {
	for i := range r.Routes {
		if r.Routes[i].matcher().match(t) {
			return r.Routes[i].Target
		}
	}
	return r.Default
}

func (r Router[T]) find(t target) Routed[T] {
	for i := range r.Routes {
		// One Matcher for both steps, even if a Live replaces it meanwhile.
		m := r.Routes[i].matcher()
		if rule, ok := m.find(t); ok {
			return Routed[T]{Target: r.Routes[i].Target, Matched: true, Index: i, Rule: rule}
		}
	}
	return Routed[T]{Target: r.Default, Index: -1}
}

func (rt *Route[T]) matcher() *Matcher { return sourceMatcher(rt.Matcher) }
