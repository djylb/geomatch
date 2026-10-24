package geomatch

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
)

func TestPolicyLists(t *testing.T) {
	allow := MustCompile([]string{"10.0.0.0/8", "domain:both.test", "domain:allowed.test"})
	deny := MustCompile([]string{"10.9.0.0/16", "domain:both.test", "domain:denied.test"})
	skipped, _ := Compile([]string{"geosite:cn"}) // no geodata
	addrs := []string{"10.1.1.1", "10.9.1.1", "both.test", "allowed.test", "denied.test", "neither.test"}
	for _, c := range []struct {
		name string
		p    Policy
		want []bool
	}{
		{"deny first", Policy{Allow: allow, Deny: deny}, []bool{true, false, false, true, false, false}},
		{"allow first", Policy{Allow: allow, Deny: deny, Priority: AllowFirst}, []bool{true, true, true, true, false, true}},
		{"unknown priority", Policy{Allow: allow, Deny: deny, Priority: 9}, []bool{true, false, false, true, false, false}},
		{"allowlist", Policy{Allow: allow, Priority: AllowFirst}, []bool{true, true, true, true, false, false}},
		{"denylist", Policy{Deny: deny}, []bool{true, false, false, true, false, true}},
		{"nil *Matcher", Policy{Allow: (*Matcher)(nil)}, []bool{true, true, true, true, true, true}},
		// Any Matcher is a set list: an allowlist of no rules allows nothing.
		{"no rules", Policy{Allow: MustCompile(nil), Deny: deny}, []bool{false, false, false, false, false, false}},
		{"comments only", Policy{Allow: MustCompile([]string{"# none", ""})}, []bool{false, false, false, false, false, false}},
		{"denylist of no rules", Policy{Deny: MustCompile(nil)}, []bool{true, true, true, true, true, true}},
		{"rules all skipped", Policy{Allow: skipped}, []bool{false, false, false, false, false, false}},
		{"nil *Live", Policy{Deny: (*Live)(nil)}, []bool{true, true, true, true, true, true}},
		{"zero", Policy{}, []bool{true, true, true, true, true, true}},
		{"Mode allowlist", ModeAllowlist.Policy(allow), []bool{true, true, true, true, false, false}},
		{"Mode allowlist without rules", ModeAllowlist.Policy(nil), []bool{false, false, false, false, false, false}},
		{"Mode allowlist of no rules", ModeAllowlist.Policy(MustCompile(nil)), []bool{false, false, false, false, false, false}},
		{"Mode denylist", ModeDenylist.Policy(deny), []bool{true, false, false, true, false, true}},
		{"Mode off", ModeOff.Policy(deny), []bool{true, true, true, true, true, true}},
	} {
		for i, addr := range addrs {
			d := c.p.Decide(addr)
			if c.p.Allows(addr) != c.want[i] || d.Allowed != c.want[i] {
				t.Errorf("%s: %q allowed = %v, Decide %v; want %v", c.name, addr, c.p.Allows(addr), d, c.want[i])
			}
		}
	}
	// The rule is of the list that decided.
	for p, want := range map[*Policy]string{
		{Allow: allow, Deny: deny}:                       "denied by domain:both.test",
		{Allow: allow, Deny: deny, Priority: AllowFirst}: "allowed by domain:both.test",
	} {
		if d := p.Decide("both.test"); d.String() != want || !d.Matched {
			t.Errorf("Decide = %q, want %q", d, want)
		}
	}
	if d := (Policy{Allow: allow, Deny: deny}).Decide("denied.test"); d.Rule.String() != "domain:denied.test" || d.Level != 0 {
		t.Errorf("Decide = %+v", d)
	}
}

func TestLevelsFirstMatch(t *testing.T) {
	global := Policy{Allow: MustCompile([]string{"10.1.0.0/16"}), Deny: MustCompile([]string{"10.0.0.0/8"}), Priority: AllowFirst}
	user := Policy{Deny: MustCompile([]string{"10.1.2.0/24", "192.0.2.0/24"})}
	tunnel := Policy{Allow: MustCompile([]string{"192.0.2.7", "198.51.100.0/24"})}
	l := Levels{FirstMatch: true, Policies: []Policy{global, user, {}, tunnel}}
	cases := []struct {
		addr    string
		allowed bool
		level   int
		rule    string
	}{
		{"10.1.2.3", true, 0, "10.1.0.0/16"}, // global allows over the user's denial
		{"10.2.0.1", false, 0, "10.0.0.0/8"},
		{"192.0.2.7", false, 1, "192.0.2.0/24"}, // the user denies over the tunnel's allowance
		{"198.51.100.9", true, 3, "198.51.100.0/24"},
		{"203.0.113.1", true, -1, ""}, // no level's rules match
	}
	for _, tc := range cases {
		d := l.Decide(tc.addr)
		if d.Allowed != tc.allowed || d.Level != tc.level || d.Rule.String() != tc.rule || l.Allows(tc.addr) != tc.allowed {
			t.Errorf("Decide(%q) = %+v, Allows %v; want %v at %d by %q", tc.addr, d, l.Allows(tc.addr), tc.allowed, tc.level, tc.rule)
		}
	}
	l.DenyUnmatched = true
	if d := l.Decide("203.0.113.1"); d.Allowed || d.Level != -1 || l.Allows("203.0.113.1") {
		t.Errorf("DenyUnmatched: %+v", d)
	}
	// Specific settings first: the tunnel overrides everything.
	rev := Levels{FirstMatch: true, Policies: []Policy{tunnel, user, global}}
	if !rev.Allows("192.0.2.7") || rev.Allows("10.1.2.3") {
		t.Error("reversed levels")
	}
	// DenyUnmatched only applies with FirstMatch.
	if !(Levels{DenyUnmatched: true}).Allows("x") {
		t.Error("DenyUnmatched without FirstMatch")
	}

	ip := netip.MustParseAddr("192.0.2.7")
	tcp := &net.TCPAddr{IP: ip.AsSlice()}
	if l.AllowsIP(ip) || l.AllowsNetAddr(tcp) || l.AllowsHostIP("", ip) || l.AllowsDomain("x.test") ||
		l.DecideIP(ip).Level != 1 || l.DecideNetAddr(tcp).Level != 1 || l.DecideHostIP("x.test", ip).Level != 1 ||
		l.DecideDomain("x.test").Level != -1 {
		t.Error("forms")
	}
}

func TestPriorityText(t *testing.T) {
	for in, want := range map[string]Priority{
		"": DenyFirst, "deny-first": DenyFirst, " Deny_First ": DenyFirst, "blacklist": DenyFirst, "deny": DenyFirst,
		"allow-first": AllowFirst, "AllowFirst": AllowFirst, "whitelist": AllowFirst, "allowlist": AllowFirst,
	} {
		if got, err := ParsePriority(in); err != nil || got != want {
			t.Errorf("ParsePriority(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParsePriority("both"); err == nil {
		t.Error("ParsePriority accepted an unknown priority")
	}
	var cfg struct{ Priority Priority }
	if err := json.Unmarshal([]byte(`{"Priority":"whitelist"}`), &cfg); err != nil || cfg.Priority != AllowFirst {
		t.Fatalf("json.Unmarshal = %v, %v", cfg.Priority, err)
	}
	if b, err := json.Marshal(cfg); err != nil || string(b) != `{"Priority":"allow-first"}` {
		t.Fatalf("json.Marshal = %s, %v", b, err)
	}
	if _, err := Priority(5).MarshalText(); err == nil || Priority(5).String() != "priority 5" {
		t.Error("unknown Priority")
	}
}
