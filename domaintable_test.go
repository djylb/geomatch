package geomatch

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// TestDomainTableAgainstNaive compares the table with checking every name.
func TestDomainTableAgainstNaive(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	label := func() string { return []string{"a", "b", "ab", "x-y", "com", "cn", "0"}[r.IntN(7)] }
	name := func() string {
		parts := make([]string, r.IntN(4)+1)
		for i := range parts {
			parts[i] = label()
		}
		return strings.Join(parts, ".")
	}
	for range 100 {
		names := map[string]uint8{}
		for range r.IntN(30) + 1 {
			names[name()] |= uint8(r.IntN(3) + 1)
		}
		table := newDomainTable(names)
		for range 200 {
			host := name()
			want := names[host]&nameExact != 0
			for n, f := range names {
				if f&nameSub != 0 && strings.HasSuffix(host, "."+n) {
					want = true
				}
			}
			if got := table.match(host); got != want {
				t.Fatalf("match(%q) = %v, want %v for %v", host, got, want, names)
			}
		}
	}
	if newDomainTable(nil) != nil {
		t.Fatal("empty table")
	}
}
