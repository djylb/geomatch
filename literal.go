package geomatch

import (
	"regexp/syntax"
	"slices"
	"strings"
)

// literalIndex finds which of a set of literal strings occur in a text in one
// pass (Aho-Corasick). Its states are stored sparsely: hosts are short, so a
// lookup walks a few edges per byte.
type literalIndex struct {
	nodes []acNode
}

type acNode struct {
	edges []acEdge // sorted by byte
	fail  int32
	dict  int32   // the nearest node on the fail chain with literals, or 0
	out   []int32 // ids of the literals ending exactly here
}

type acEdge struct {
	b  byte
	to int32
}

func (n *acNode) step(b byte) (int32, bool) {
	for _, e := range n.edges {
		if e.b == b {
			return e.to, true
		}
		if e.b > b {
			break
		}
	}
	return 0, false
}

// newLiteralIndex indexes lits; a hit reports the literal's position in lits.
func newLiteralIndex(lits []string) *literalIndex {
	x := &literalIndex{nodes: []acNode{{}}}
	for id, lit := range lits {
		s := int32(0)
		for i := range len(lit) {
			t, ok := x.nodes[s].step(lit[i])
			if !ok {
				t = int32(len(x.nodes))
				x.nodes = append(x.nodes, acNode{})
				n := &x.nodes[s]
				at, _ := slices.BinarySearchFunc(n.edges, lit[i], func(e acEdge, b byte) int { return int(e.b) - int(b) })
				n.edges = slices.Insert(n.edges, at, acEdge{lit[i], t})
			}
			s = t
		}
		x.nodes[s].out = append(x.nodes[s].out, int32(id))
	}
	// Breadth-first: a node's fail link is the longest proper suffix of its
	// path that is also a path, and its dictionary link the nearest node on
	// that chain where literals end, so that outputs are not copied.
	queue := make([]int32, 0, len(x.nodes))
	for _, e := range x.nodes[0].edges {
		queue = append(queue, e.to)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, e := range x.nodes[s].edges {
			f := x.nodes[s].fail
			for {
				if t, ok := x.nodes[f].step(e.b); ok {
					x.nodes[e.to].fail = t
					break
				}
				if f == 0 {
					break
				}
				f = x.nodes[f].fail
			}
			child := &x.nodes[e.to]
			if fail := &x.nodes[child.fail]; len(fail.out) > 0 {
				child.dict = child.fail
			} else {
				child.dict = fail.dict
			}
			queue = append(queue, e.to)
		}
	}
	return x
}

// scan calls hit with the id of every literal occurrence in text until hit
// returns true, and reports whether it did.
func (x *literalIndex) scan(text string, hit func(id int32) bool) bool {
	s := int32(0)
	for i := range len(text) {
		b := text[i]
		for {
			if t, ok := x.nodes[s].step(b); ok {
				s = t
				break
			}
			if s == 0 {
				break
			}
			s = x.nodes[s].fail
		}
		for d := s; d != 0; d = x.nodes[d].dict {
			for _, id := range x.nodes[d].out {
				if hit(id) {
					return true
				}
			}
		}
	}
	return false
}

// requiredLiteral returns an ASCII text, lowercase, that every match of the
// regular expression pattern contains, or "" if it finds none of at least
// three bytes. It looks at the top-level sequence of the expression only.
func requiredLiteral(pattern string) string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ""
	}
	lit := longestRequired(re.Simplify())
	if len(lit) < 3 {
		return ""
	}
	for i := range len(lit) {
		if lit[i] >= 0x80 {
			return "" // case folding outside ASCII is not byte-for-byte
		}
	}
	return strings.ToLower(lit)
}

func longestRequired(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCapture, syntax.OpPlus:
		return longestRequired(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return longestRequired(re.Sub[0])
		}
	case syntax.OpConcat:
		best := ""
		for _, sub := range re.Sub {
			if s := longestRequired(sub); len(s) > len(best) {
				best = s
			}
		}
		return best
	}
	return ""
}
