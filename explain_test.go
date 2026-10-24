package geomatch

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

// linearFirst is the rule-by-rule search that explainIndex replaces.
func linearFirst(m *Matcher, t target) int {
	for i := range m.probes {
		if m.probes[i].match(t) {
			return i
		}
	}
	return -1
}

// TestExplainIndexAgrees compares the index with trying the rules in order,
// on random rules and targets.
func TestExplainIndexAgrees(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	labels := []string{"a", "b", "ab", "cn", "x", "ba"}
	name := func() string {
		n := 1 + rng.IntN(3)
		s := labels[rng.IntN(len(labels))]
		for range n - 1 {
			s += "." + labels[rng.IntN(len(labels))]
		}
		return s
	}
	addr := func() netip.Addr {
		if rng.IntN(4) == 0 {
			return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(rng.IntN(4))})
		}
		return netip.AddrFrom4([4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(4)), byte(rng.IntN(8))})
	}
	for round := range 300 {
		var rules []string
		for range 1 + rng.IntN(30) {
			switch rng.IntN(8) {
			case 0:
				a := addr()
				rules = append(rules, netip.PrefixFrom(a, []int{8, 16, 24, 30, 32}[rng.IntN(5)]+map[bool]int{true: 96}[a.Is6()]).Masked().String())
			case 1:
				rules = append(rules, "full:"+name())
			case 2:
				rules = append(rules, "domain:"+name())
			case 3:
				rules = append(rules, "*."+name())
			case 4:
				rules = append(rules, "keyword:"+labels[rng.IntN(len(labels))])
			case 5:
				rules = append(rules, "regexp:^"+labels[rng.IntN(len(labels))])
			case 6:
				rules = append(rules, "dotless:"+labels[rng.IntN(len(labels))])
			default:
				rules = append(rules, name())
			}
		}
		m, err := Compile(rules)
		if err != nil {
			t.Fatalf("Compile(%q): %v", rules, err)
		}
		m.once.Do(m.buildExplain)
		for range 50 {
			var tg target
			if rng.IntN(2) == 0 {
				tg = ipTarget(addr())
			} else {
				tg = target{host: name()}
			}
			if got, want := m.explain.first(m.probes, tg), linearFirst(m, tg); got != want {
				t.Fatalf("round %d, rules %q, target %+v: index finds %d, in order %d", round, rules, tg, got, want)
			}
		}
	}
}

func BenchmarkDecideManyRules(b *testing.B) {
	rules := make([]string, 20000)
	for i := range rules {
		rules[i] = fmt.Sprintf("domain:host%d.example", i)
	}
	p := Policy{Allow: MustCompile(rules)}
	b.Run("Allows", func(b *testing.B) {
		for b.Loop() {
			p.Allows("www.host19999.example")
		}
	})
	b.Run("Decide", func(b *testing.B) {
		for b.Loop() {
			p.Decide("www.host19999.example")
		}
	})
}
