package geomatch

import (
	"net/netip"
	"strconv"
)

// Mode is how a Policy uses its rules.
type Mode uint8

// Policy modes. Their values are stable, for configuration files.
const (
	// Off allows everything.
	Off Mode = iota
	// Allowlist allows only what matches; with no rules it allows nothing.
	Allowlist
	// Denylist allows everything except what matches.
	Denylist
)

func (m Mode) String() string {
	switch m {
	case Off:
		return "off"
	case Allowlist:
		return "allowlist"
	case Denylist:
		return "denylist"
	default:
		return "mode " + strconv.Itoa(int(m))
	}
}

// Policy allows or denies addresses by rules. The zero Policy allows
// everything.
type Policy struct {
	Mode  Mode
	Rules *Matcher
}

// Allows reports whether the policy allows addr, which Matcher.Match reads.
// An address that cannot be read matches no rule. Unknown modes allow
// everything, like Off.
func (p Policy) Allows(addr string) bool {
	switch p.Mode {
	case Allowlist:
		return p.Rules.Match(addr)
	case Denylist:
		return !p.Rules.Match(addr)
	default:
		return true
	}
}

// AllowsIP reports whether the policy allows ip.
func (p Policy) AllowsIP(ip netip.Addr) bool {
	switch p.Mode {
	case Allowlist:
		return p.Rules.MatchIP(ip)
	case Denylist:
		return !p.Rules.MatchIP(ip)
	default:
		return true
	}
}
