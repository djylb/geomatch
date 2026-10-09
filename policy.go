package geomatch

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
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

//goland:noinspection GoMixedReceiverTypes
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

// ParseMode parses a mode from its name, its number, or a common synonym:
// off, none, disabled or 0; allowlist, allow, whitelist or 1; denylist,
// deny, blocklist, blacklist or 2. Case and surrounding spaces are ignored.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "disabled", "0", "":
		return Off, nil
	case "allowlist", "allow", "whitelist", "1":
		return Allowlist, nil
	case "denylist", "deny", "blocklist", "blacklist", "2":
		return Denylist, nil
	}
	return Off, fmt.Errorf("geomatch: unknown policy mode %q", s)
}

// MarshalText returns the name of m, for configuration files.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mode) MarshalText() ([]byte, error) {
	if m > Denylist {
		return nil, fmt.Errorf("geomatch: unknown policy mode %d", m)
	}
	return []byte(m.String()), nil
}

// UnmarshalText sets m from what ParseMode reads. Like time.Time, Mode has a
// pointer receiver here only, so that values print and marshal by name.
//
//goland:noinspection GoMixedReceiverTypes
func (m *Mode) UnmarshalText(text []byte) error {
	mode, err := ParseMode(string(text))
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

// UnmarshalJSON sets m from a JSON string that ParseMode reads or from a
// JSON number 0 to 2. A JSON null leaves m unchanged.
//
//goland:noinspection GoMixedReceiverTypes
func (m *Mode) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var err error
		if s, err = strconv.Unquote(s); err != nil {
			return fmt.Errorf("geomatch: policy mode %s: %w", b, err)
		}
	}
	return m.UnmarshalText([]byte(s))
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

// AllowsNetAddr reports whether the policy allows a, such as a connection's
// RemoteAddr, which Matcher.MatchNetAddr reads.
func (p Policy) AllowsNetAddr(a net.Addr) bool {
	switch p.Mode {
	case Allowlist:
		return p.Rules.MatchNetAddr(a)
	case Denylist:
		return !p.Rules.MatchNetAddr(a)
	default:
		return true
	}
}

// Decision is a Policy's answer for an address, with the rule that decided.
type Decision struct {
	Allowed bool
	// Matched reports whether a rule matched; Rule is the first one.
	Matched bool
	Rule    Rule
}

// Decide is Allows that also reports the first rule addr matched, for
// logging. Off decides without looking at the rules.
func (p Policy) Decide(addr string) Decision {
	if p.Mode != Allowlist && p.Mode != Denylist {
		return Decision{Allowed: true}
	}
	rule, matched := p.Rules.MatchRule(addr)
	return Decision{Allowed: matched == (p.Mode == Allowlist), Matched: matched, Rule: rule}
}
