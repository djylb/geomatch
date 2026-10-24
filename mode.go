package geomatch

import (
	"fmt"
	"strconv"
	"strings"
)

// Mode is how one list of rules is used, as configuration that has a mode
// and rules describes it; Mode.Policy makes the Policy.
type Mode uint8

// Modes. Their values are stable, for configuration files.
const (
	// ModeOff allows everything.
	ModeOff Mode = iota
	// ModeAllowlist allows only what matches; with no rules it allows
	// nothing.
	ModeAllowlist
	// ModeDenylist allows everything except what matches.
	ModeDenylist
)

// Policy returns the Policy of mode m over rules: an allowlist, a denylist,
// or for ModeOff and unknown modes one that allows everything. An allowlist
// with nil rules allows nothing.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mode) Policy(rules MatcherSource) Policy {
	switch m {
	case ModeAllowlist:
		return Policy{Allow: allowlist{rules}}
	case ModeDenylist:
		return Policy{Deny: rules}
	default:
		return Policy{}
	}
}

//goland:noinspection GoMixedReceiverTypes
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAllowlist:
		return "allowlist"
	case ModeDenylist:
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
		return ModeOff, nil
	case "allowlist", "allow", "whitelist", "1":
		return ModeAllowlist, nil
	case "denylist", "deny", "blocklist", "blacklist", "2":
		return ModeDenylist, nil
	}
	return ModeOff, fmt.Errorf("geomatch: unknown policy mode %q", s)
}

// MarshalText returns the name of m, for configuration files.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mode) MarshalText() ([]byte, error) {
	if m > ModeDenylist {
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
	return unmarshalJSONText(b, m.UnmarshalText)
}

// unmarshalJSONText reads a JSON string or number b as text, which a JSON
// null leaves unread.
func unmarshalJSONText(b []byte, unmarshal func([]byte) error) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var err error
		if s, err = strconv.Unquote(s); err != nil {
			return fmt.Errorf("geomatch: %s: %w", b, err)
		}
	}
	return unmarshal([]byte(s))
}

// Priority decides for an address on both lists of a Policy. Unknown
// priorities count as DenyFirst.
type Priority uint8

// Priorities. Their values are stable, for configuration files.
const (
	// DenyFirst lets the denylist win: an address is allowed only if it is
	// on the allowlist and not on the denylist. Addresses on neither list
	// are denied, as an allowlist does.
	DenyFirst Priority = iota
	// AllowFirst lets the allowlist win: an address is denied only if it is
	// on the denylist and not on the allowlist. Addresses on neither list
	// are allowed, as a denylist does; otherwise the denylist would change
	// nothing.
	AllowFirst
)

//goland:noinspection GoMixedReceiverTypes
func (p Priority) String() string {
	switch p {
	case DenyFirst:
		return "deny-first"
	case AllowFirst:
		return "allow-first"
	default:
		return fmt.Sprintf("priority %d", uint8(p))
	}
}

// ParsePriority parses a priority from its name or the list that wins:
// deny-first, deny, denylist, blacklist or 0; allow-first, allow, allowlist,
// whitelist or 1. Case, surrounding spaces, and - or _ in names are ignored;
// an empty string is DenyFirst.
func ParsePriority(s string) (Priority, error) {
	switch strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(s))) {
	case "denyfirst", "deny", "denylist", "blacklist", "blocklist", "0", "":
		return DenyFirst, nil
	case "allowfirst", "allow", "allowlist", "whitelist", "1":
		return AllowFirst, nil
	}
	return DenyFirst, fmt.Errorf("geomatch: unknown priority %q", s)
}

// MarshalText returns the name of p, for configuration files.
//
//goland:noinspection GoMixedReceiverTypes
func (p Priority) MarshalText() ([]byte, error) {
	if p > AllowFirst {
		return nil, fmt.Errorf("geomatch: unknown priority %d", uint8(p))
	}
	return []byte(p.String()), nil
}

// UnmarshalText sets p from what ParsePriority reads.
//
//goland:noinspection GoMixedReceiverTypes
func (p *Priority) UnmarshalText(text []byte) error {
	v, err := ParsePriority(string(text))
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// UnmarshalJSON sets p from a JSON string that ParsePriority reads or from a
// JSON number 0 or 1. A JSON null leaves p unchanged.
//
//goland:noinspection GoMixedReceiverTypes
func (p *Priority) UnmarshalJSON(b []byte) error {
	return unmarshalJSONText(b, p.UnmarshalText)
}

// allowlist is the list of an allowlist Mode, which is set even without
// rules, so that it allows nothing.
type allowlist struct{ rules MatcherSource }

// matchNothing is a set list without rules.
var matchNothing = &Matcher{}

func (a allowlist) Matcher() *Matcher {
	if m := sourceMatcher(a.rules); m != nil {
		return m
	}
	return matchNothing
}
