package geomatch

import (
	"net"
	"net/netip"
	"strconv"
)

// Policy allows or denies addresses by an allowlist, a denylist, or both:
//
//   - With only Allow, it allows the addresses that Allow matches.
//   - With only Deny, it allows all but those that Deny matches.
//   - With both, an address that one matches gets that list's answer, and
//     Priority decides for one that both match. Addresses that neither
//     matches are denied with DenyFirst, as an allowlist with exceptions
//     denies them, and allowed with AllowFirst, as a denylist with
//     exceptions allows them.
//   - With neither, as the zero Policy, it allows everything.
//
// A list is not set if it is nil, a nil *Matcher, or compiled from no rules,
// as configuration without that list gives, so that compiling every list of
// the configuration is enough. A list whose rules were all skipped, such as
// for missing geodata, is set and matches nothing: an allowlist then allows
// nothing rather than everything. Mode.Policy makes the Policy of
// configuration that has a mode and rules, where an allowlist without rules
// allows nothing.
//
// Like those of Matcher, its methods come in five forms, by the kind of
// address. Allows reports whether an address is allowed, and Decide also
// which rule decided, at more cost when a rule matches.
type Policy struct {
	// Allow and Deny are the lists: a *Matcher, or a *Live, whose Matcher
	// the policy then follows as geodata changes.
	Allow MatcherSource
	Deny  MatcherSource
	// Priority decides for an address that both lists match.
	Priority Priority
}

// MatcherSource provides a Matcher to a Policy or a Router: a *Matcher
// provides itself, and a *Live its current Matcher.
type MatcherSource interface {
	Matcher() *Matcher
}

// sourceMatcher returns the Matcher of s, or nil.
func sourceMatcher(s MatcherSource) *Matcher {
	if s == nil {
		return nil
	}
	return s.Matcher()
}

// Allows reports whether the policy allows addr, as Matcher.Match reads it.
// An address that cannot be read matches no rule.
func (p Policy) Allows(addr string) bool { return p.allows(addrTarget(addr)) }

// AllowsIP reports whether the policy allows ip.
func (p Policy) AllowsIP(ip netip.Addr) bool { return p.allows(ipTarget(ip)) }

// AllowsDomain reports whether the policy allows host, as
// Matcher.MatchDomain reads it.
func (p Policy) AllowsDomain(host string) bool { return p.allows(domainTarget(host)) }

// AllowsNetAddr reports whether the policy allows a, such as a connection's
// RemoteAddr, as Matcher.MatchNetAddr reads it.
func (p Policy) AllowsNetAddr(a net.Addr) bool { return p.allows(netAddrTarget(a)) }

// AllowsHostIP reports whether the policy allows a domain name and the IP
// address it resolved to, as Matcher.MatchHostIP reads them: a list matches
// them if it matches either.
func (p Policy) AllowsHostIP(host string, ip netip.Addr) bool {
	return p.allows(hostIPTarget(host, ip))
}

// Decision is the answer of a Policy or Levels for an address, with the rule
// that decided.
type Decision struct {
	Allowed bool
	// Matched reports whether a rule decided; Rule is that rule, of the
	// allowlist if Allowed and of the denylist otherwise.
	Matched bool
	Rule    Rule
	// Level is the index of the policy that decided among Levels, or -1 if
	// none did. It is 0 for a single Policy.
	Level int
	// LevelName is the name of that level, from Levels.Names, or "".
	LevelName string
}

// String describes d for logs, as "denied by geoip:cn (user)" or "allowed:
// no rule matched"; it names the level by LevelName, or else by number
// after the first.
func (d Decision) String() string {
	verdict := "denied"
	if d.Allowed {
		verdict = "allowed"
	}
	level := ""
	switch {
	case d.LevelName != "":
		level = " (" + d.LevelName + ")"
	case d.Level > 0:
		level = " (level " + strconv.Itoa(d.Level) + ")"
	}
	if !d.Matched {
		return verdict + ": no rule matched" + level
	}
	return verdict + " by " + d.Rule.String() + level
}

// Decide is Allows that also reports the rule that decided, for logging.
func (p Policy) Decide(addr string) Decision { return p.decide(addrTarget(addr)) }

// DecideIP is Decide for an IP address.
func (p Policy) DecideIP(ip netip.Addr) Decision { return p.decide(ipTarget(ip)) }

// DecideDomain is Decide for a domain name.
func (p Policy) DecideDomain(host string) Decision { return p.decide(domainTarget(host)) }

// DecideNetAddr is Decide for a net.Addr.
func (p Policy) DecideNetAddr(a net.Addr) Decision { return p.decide(netAddrTarget(a)) }

// DecideHostIP is Decide for a domain name and its IP address.
func (p Policy) DecideHostIP(host string, ip netip.Addr) Decision {
	return p.decide(hostIPTarget(host, ip))
}

// lists returns the lists of p in the order they decide: the winning one
// first, with the answer of each.
func (p Policy) lists() (first, second MatcherSource, firstAllows bool) {
	if p.Priority == AllowFirst {
		return p.Allow, p.Deny, true
	}
	return p.Deny, p.Allow, false
}

// unmatched reports whether p allows addresses that neither list matches.
func (p Policy) unmatched() bool {
	return !isSet(p.Allow) || isSet(p.Deny) && p.Priority == AllowFirst
}

// isSet reports whether s is a list that is set.
func isSet(s MatcherSource) bool {
	m := sourceMatcher(s)
	return m != nil && !m.noRules
}

// match reports whether a rule of p matches t, and if so whether p allows
// it.
func (p Policy) match(t target) (allowed, matched bool) {
	first, second, firstAllows := p.lists()
	if sourceMatcher(first).match(t) {
		return firstAllows, true
	}
	if sourceMatcher(second).match(t) {
		return !firstAllows, true
	}
	return false, false
}

func (p Policy) allows(t target) bool {
	if allowed, ok := p.match(t); ok {
		return allowed
	}
	return p.unmatched()
}

// find is match that also returns the rule.
func (p Policy) find(t target) (Decision, bool) {
	first, second, firstAllows := p.lists()
	// One Matcher for both steps of find, even if a Live replaces it.
	if rule, ok := sourceMatcher(first).find(t); ok {
		return Decision{Allowed: firstAllows, Matched: true, Rule: rule}, true
	}
	if rule, ok := sourceMatcher(second).find(t); ok {
		return Decision{Allowed: !firstAllows, Matched: true, Rule: rule}, true
	}
	return Decision{}, false
}

func (p Policy) decide(t target) Decision {
	if d, ok := p.find(t); ok {
		return d
	}
	return Decision{Allowed: p.unmatched()}
}
