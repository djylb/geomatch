package geomatch

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
)

// liveBenchRules returns n distinct rules, half address prefixes and half
// domain rules, as a large list of a running program holds.
func liveBenchRules(n int) []string {
	rules := make([]string, n)
	for i := range rules {
		if i%2 == 0 {
			rules[i] = fmt.Sprintf("%d.%d.%d.0/24", 1+i>>16&0xff, i>>8&0xff, i&0xff)
		} else {
			rules[i] = fmt.Sprintf("domain:site%d.example", i)
		}
	}
	return rules
}

var liveBenchSizes = []int{10, 1000, 100000, 1000000}

// BenchmarkLiveUpdate measures a change of one rule, which Update applies
// by compiling every rule again.
func BenchmarkLiveUpdate(b *testing.B) {
	for _, n := range liveBenchSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			rules := liveBenchRules(n)
			l, err := NewLive(Compiler{}, rules)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				rules[0] = fmt.Sprintf("domain:changed%d.example", i)
				i++
				if err := l.Update(rules); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParseRulesScale measures the parsing share of a compile, which
// is all that a cache of parsed rules could save.
func BenchmarkParseRulesScale(b *testing.B) {
	for _, n := range liveBenchSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			rules := liveBenchRules(n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ParseRules(rules); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestCompileProbesSizedOnce checks that a compile keeps one probe per rule
// without growing the list by append, which copied a large list over and
// over, and keeps no room for rules it skipped.
func TestCompileProbesSizedOnce(t *testing.T) {
	const n = 20000
	rules := liveBenchRules(n)
	if _, err := Compile(rules); err != nil { // warm up
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	m, err := Compile(rules)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := (after.TotalAlloc - before.TotalAlloc) / n; got > 800 {
		t.Errorf("Compile allocated %d bytes a rule", got)
	}
	if len(m.probes) != n || cap(m.probes) != n {
		t.Errorf("probes len %d cap %d, want %d", len(m.probes), cap(m.probes), n)
	}

	mostlyComments := make([]string, 1000)
	for i := range mostlyComments {
		mostlyComments[i] = "# comment"
	}
	mostlyComments[0] = "domain:example.com"
	m = MustCompile(mostlyComments)
	if len(m.probes) != 1 || cap(m.probes) != 1 {
		t.Errorf("probes len %d cap %d, want 1", len(m.probes), cap(m.probes))
	}
}
