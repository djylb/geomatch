package geomatch

import (
	"net"
	"net/netip"
)

// Levels apply policies of several levels, such as global, per-user,
// per-client and per-resource ones, in one of two ways:
//
//   - By default every level must allow an address, so that a level can only
//     narrow what those before it allow: an administrator's global denylist
//     binds every user.
//   - With FirstMatch the first level whose rules match an address decides,
//     overriding the levels after it either way. List the levels most
//     authoritative first, or most specific first for settings that override
//     general ones. Addresses that no level's rules match are allowed, or
//     denied with DenyUnmatched.
//
// A level that is not set, the zero Policy, never matches and allows
// everything, so it changes nothing either way. Decision.Level tells which
// level decided, and Decision.Name its Policy.Name. The methods take the forms of those of Policy, and read the
// address once. Levels are safe for concurrent use while their fields are
// not changed.
type Levels struct {
	Policies []Policy
	// FirstMatch lets the first level whose rules match decide, rather than
	// requiring every level to allow.
	FirstMatch bool
	// DenyUnmatched, with FirstMatch, denies addresses that no level's rules
	// match, which are otherwise allowed.
	DenyUnmatched bool
}

// Allows reports whether the levels allow addr, as Matcher.Match reads it.
func (l Levels) Allows(addr string) bool { return l.allows(addrTarget(addr)) }

// AllowsIP reports whether the levels allow ip.
func (l Levels) AllowsIP(ip netip.Addr) bool { return l.allows(ipTarget(ip)) }

// AllowsDomain reports whether the levels allow host.
func (l Levels) AllowsDomain(host string) bool { return l.allows(domainTarget(host)) }

// AllowsNetAddr reports whether the levels allow a.
func (l Levels) AllowsNetAddr(a net.Addr) bool { return l.allows(netAddrTarget(a)) }

// AllowsHostIP reports whether the levels allow a domain name and its IP
// address.
func (l Levels) AllowsHostIP(host string, ip netip.Addr) bool {
	return l.allows(hostIPTarget(host, ip))
}

// Decide is Allows that also reports the level and rule that decided: the
// level that denied, or the first whose rule matched; Level is -1 if no
// level's rule matched and none denied.
func (l Levels) Decide(addr string) Decision { return l.decide(addrTarget(addr)) }

// DecideIP is Decide for an IP address.
func (l Levels) DecideIP(ip netip.Addr) Decision { return l.decide(ipTarget(ip)) }

// DecideDomain is Decide for a domain name.
func (l Levels) DecideDomain(host string) Decision { return l.decide(domainTarget(host)) }

// DecideNetAddr is Decide for a net.Addr.
func (l Levels) DecideNetAddr(a net.Addr) Decision { return l.decide(netAddrTarget(a)) }

// DecideHostIP is Decide for a domain name and its IP address.
func (l Levels) DecideHostIP(host string, ip netip.Addr) Decision {
	return l.decide(hostIPTarget(host, ip))
}

func (l Levels) allows(t target) bool {
	for i := range l.Policies {
		p := &l.Policies[i]
		if !l.FirstMatch {
			if !p.allows(t) {
				return false
			}
			continue
		}
		if allowed, ok := p.match(t); ok {
			return allowed
		}
	}
	return !l.FirstMatch || !l.DenyUnmatched
}

func (l Levels) decide(t target) Decision {
	out := Decision{Allowed: true, Level: -1}
	if l.FirstMatch {
		out.Allowed = !l.DenyUnmatched
	}
	for i := range l.Policies {
		p := &l.Policies[i]
		if l.FirstMatch {
			if d, ok := p.find(t); ok {
				return l.at(d, i)
			}
			continue
		}
		d := p.decide(t)
		if !d.Allowed {
			return l.at(d, i)
		}
		if d.Matched && out.Level < 0 {
			out = l.at(d, i)
		}
	}
	return out
}

// at returns d as the decision of level i.
func (l Levels) at(d Decision, i int) Decision {
	d.Level = i
	return d
}
