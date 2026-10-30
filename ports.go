package geomatch

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// PortRange is a range of ports, First to Last inclusive, of Rule.Ports.
type PortRange struct {
	First, Last uint16
}

// String returns the range as a rule writes it: 443 or 8000-9000.
func (r PortRange) String() string {
	if r.First == r.Last {
		return strconv.Itoa(int(r.First))
	}
	return strconv.Itoa(int(r.First)) + "-" + strconv.Itoa(int(r.Last))
}

// SyntaxError is the cause of a rule whose ports or address range cannot be
// read, and where: Offset is the byte offset in the rule as RuleError.Rule
// quotes it.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("at byte %d: %s", e.Offset, e.Msg)
}

func syntaxErr(off int, format string, args ...any) error {
	return &SyntaxError{Offset: off, Msg: fmt.Sprintf(format, args...)}
}

// portsText writes ports as a rule does: 80,443,8000-9000.
func portsText(ports []PortRange) string {
	var b strings.Builder
	for i, r := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(r.String())
	}
	return b.String()
}

// parsePorts reads a port list, which starts at byte off of the rule.
func parsePorts(text string, off int) ([]PortRange, error) {
	var out []PortRange
	for {
		item, rest, more := strings.Cut(text, ",")
		first, last, ranged := strings.Cut(item, "-")
		lo, err := parsePortNumber(first, off)
		if err != nil {
			return nil, err
		}
		hi := lo
		if ranged {
			if hi, err = parsePortNumber(last, off+len(first)+1); err != nil {
				return nil, err
			}
			if lo > hi {
				return nil, syntaxErr(off, "port range %d-%d ends before it starts", lo, hi)
			}
		}
		out = append(out, PortRange{lo, hi})
		if !more {
			break
		}
		off += len(item) + 1
		text = rest
		if text == "" {
			return nil, syntaxErr(off, "empty port after ,")
		}
	}
	return normalPorts(out), nil
}

// parsePortNumber reads a decimal port, with spaces around it, at byte off.
func parsePortNumber(s string, off int) (uint16, error) {
	t := strings.TrimLeft(s, " \t")
	off += len(s) - len(t)
	t = strings.TrimRight(t, " \t")
	if t == "" {
		return 0, syntaxErr(off, "empty port")
	}
	v := 0
	for i := range len(t) {
		if t[i] < '0' || t[i] > '9' {
			return 0, syntaxErr(off+i, "invalid port %q", t)
		}
		if v = v*10 + int(t[i]-'0'); v > 65535 {
			return 0, syntaxErr(off, "port %s out of range", t)
		}
	}
	return uint16(v), nil
}

// normalPorts sorts and merges ports, overlapping and adjacent ranges
// alike. Every port is no condition: it returns nil.
func normalPorts(ports []PortRange) []PortRange {
	if len(ports) == 0 {
		return nil
	}
	ports = slices.Clone(ports)
	slices.SortFunc(ports, func(a, b PortRange) int { return cmp.Compare(a.First, b.First) })
	out := ports[:1]
	for _, r := range ports[1:] {
		last := &out[len(out)-1]
		if last.Last == 65535 || r.First <= last.Last+1 {
			last.Last = max(last.Last, r.Last)
			continue
		}
		out = append(out, r)
	}
	if len(out) == 1 && out[0] == (PortRange{0, 65535}) {
		return nil
	}
	return slices.Clip(out)
}

// allPorts are the ports of a port rule of every port, which keeps them, so
// that it matches only queries with a port, as other port rules do.
var allPorts = []PortRange{{0, 65535}}

// portsHold reports whether ports allow port, a query port as target.portOf
// returns it. Without a port, allow tells: an allowlist is satisfied and
// other lists are not; with a port that cannot be read, the reverse, so that
// both fail closed.
func portsHold(ports []PortRange, port int32, allow bool) bool {
	switch {
	case len(ports) == 0:
		return true
	case port == portNone:
		return allow
	case port == portBad:
		return !allow
	}
	p := uint16(port)
	i, _ := slices.BinarySearchFunc(ports, p, func(r PortRange, p uint16) int {
		if r.Last < p {
			return -1
		}
		return 1
	})
	return i < len(ports) && ports[i].First <= p
}

// portsAllowed reports whether r may have ports: not regexp:
// and ext rules, whose text may hold colons, nor geo rules of another file.
func portsAllowed(r *Rule) bool {
	switch r.Kind {
	case RuleRegexp, RuleExt:
		return false
	case RuleGeoIP, RuleGeoSite:
		return r.File == ""
	case RuleIP, RuleFull, RuleDomain, RuleSubdomain, RuleKeyword, RuleDotless, RulePort:
		return true
	default:
		return false
	}
}

// Query ports, as target.portOf returns them.
const (
	portNone = -1 // the query has no port
	portBad  = -2 // the query has a port that cannot be read
)

// queryPort reads the port of addr as Match does: a port, portNone or
// portBad.
func queryPort(addr string) int32 {
	_, port := hostPortOf(addr)
	t := target{port: port}
	return t.portOf()
}

// portField reads the port of an address as target.port holds it: port is
// the text after the host, as ":443", or "" for none, and scheme the scheme
// of a URL, whose default port is the port without one.
func portField(scheme, port string) int32 {
	if port == "" || port == ":" {
		if p := schemePort(scheme); p >= 0 {
			return p + 1
		}
		if port == "" {
			return 0
		}
		return -1
	}
	if port[0] != ':' {
		return -1 // text after ] that is no port
	}
	v := int32(0)
	for i := 1; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return -1
		}
		if v = v*10 + int32(port[i]-'0'); v > 65535 {
			return -1
		}
	}
	return v + 1
}

// portText finds the port of addr as hostPortOf does: the text after the
// host, as ":443", at byte off of addr, or "" for none; scheme is the
// scheme of a URL. Rules read it to know where their ports are.
func portText(addr string) (scheme, port string, off int) {
	s := strings.TrimLeftFunc(addr, unicode.IsSpace)
	off = len(addr) - len(s)
	s = strings.TrimRightFunc(s, unicode.IsSpace)
	if i := strings.Index(s, "://"); i >= 0 && !strings.ContainsAny(s[:i], "/?#\\") {
		scheme, s, off = s[:i], s[i+3:], off+i+3
	} else if strings.HasPrefix(s, "//") {
		s, off = s[2:], off+2
	}
	if i := strings.IndexAny(s, "/?#\\"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s, off = s[i+1:], off+i+1
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i >= 0 {
			return scheme, s[i+1:], off + i + 1
		}
		return "", "", 0 // no host, so no port either
	}
	if i := strings.IndexByte(s, ':'); i >= 0 && strings.LastIndexByte(s, ':') == i {
		return scheme, s[i:], off + i
	}
	return scheme, "", 0 // no port, or a bare IPv6 address
}

// schemePort returns the default port of a URL scheme that has one.
func schemePort(scheme string) int32 {
	switch {
	case scheme == "":
		return portNone
	case strings.EqualFold(scheme, "http"), strings.EqualFold(scheme, "ws"):
		return 80
	case strings.EqualFold(scheme, "https"), strings.EqualFold(scheme, "wss"):
		return 443
	case strings.EqualFold(scheme, "ftp"):
		return 21
	}
	return portNone
}

// portIndex holds the rules of a Matcher that have ports, so that a Matcher
// without them is queried as before. Rules with the same ports form a
// group, compiled without their ports; the ports of all groups split the
// port space into intervals, and each interval lists the groups whose ports
// hold it, so that a query looks up its port's interval by binary search and
// queries those groups only.
type portIndex struct {
	starts []uint16   // the first port of each interval; starts[0] is 0
	cover  [][]uint32 // the groups of each interval, or nil: see fallback
	groups []portGroup
	all    *Matcher // every rule with ports, without them
	// fallback is set when the intervals times the groups would take too
	// much memory, as with many nested ranges: queries then test the ports
	// of every group.
	fallback bool
}

type portGroup struct {
	ports []PortRange
	m     *Matcher
}

// maxCover bounds the entries of portIndex.cover, against the quadratic
// size that many nested ranges give.
var maxCover = 1 << 22

func newPortIndex(groups []portGroup, all *Matcher) *portIndex {
	x := &portIndex{groups: groups, all: all}
	var cuts []int
	for _, g := range groups {
		for _, r := range g.ports {
			cuts = append(cuts, int(r.First), int(r.Last)+1)
		}
	}
	cuts = append(cuts, 0)
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	if cuts[len(cuts)-1] == 65536 {
		cuts = cuts[:len(cuts)-1]
	}
	if len(cuts)*len(groups) > maxCover {
		x.fallback = true
		return x
	}
	x.starts = make([]uint16, len(cuts))
	x.cover = make([][]uint32, len(cuts))
	var prev []uint32
	for i, c := range cuts {
		x.starts[i] = uint16(c)
		var list []uint32
		for g := range groups {
			if portsHold(groups[g].ports, int32(c), false) {
				list = append(list, uint32(g))
			}
		}
		if slices.Equal(list, prev) {
			list = prev // shared by intervals that differ in no group
		}
		x.cover[i], prev = list, list
	}
	return x
}

// match reports whether a rule with ports matches t, whose port is port.
func (x *portIndex) match(t target, port int32, allow bool) bool {
	if port < 0 {
		// Without a port only allowlists, and with one that cannot be read
		// only other lists, take the rules as matching, as portsHold does.
		return (port == portNone) == allow && x.all.matchAny(t)
	}
	if x.fallback {
		for i := range x.groups {
			if portsHold(x.groups[i].ports, port, allow) && x.groups[i].m.matchAny(t) {
				return true
			}
		}
		return false
	}
	i, found := slices.BinarySearch(x.starts, uint16(port))
	if !found {
		i--
	}
	for _, g := range x.cover[i] {
		if x.groups[g].m.matchAny(t) {
			return true
		}
	}
	return false
}

// rangeRule returns the RuleIP of the addresses first to last, in its normal
// form: a CIDR prefix or an address if the range is one.
func rangeRule(first, last netip.Addr) (Rule, error) {
	first, last = normalAddr(first), normalAddr(last)
	switch {
	case !first.IsValid() || !last.IsValid():
		return Rule{}, errors.New("invalid address range")
	case first.Is4() != last.Is4():
		return Rule{}, fmt.Errorf("address range %v-%v mixes IPv4 and IPv6", first, last)
	case last.Less(first):
		return Rule{}, fmt.Errorf("address range %v-%v ends before it starts", first, last)
	}
	if ps := rangePrefixes(first, last, nil); len(ps) == 1 {
		return Rule{Kind: RuleIP, Prefix: ps[0]}, nil
	}
	return Rule{Kind: RuleIP, Prefix: netip.PrefixFrom(first, first.BitLen()), Last: last}, nil
}

// rangePrefixes appends the CIDR prefixes that cover first to last exactly,
// at most two for each prefix length.
func rangePrefixes(first, last netip.Addr, out []netip.Prefix) []netip.Prefix {
	lo, hi, n := u128From(first), u128From(last), 128
	if first.Is4() {
		n = 32
	}
	for {
		// The largest block that starts at lo and ends within hi.
		size := min(trailingZeros128(lo, n), n)
		for size > 0 && blockEnd(lo, size).cmp(hi) > 0 {
			size--
		}
		out = append(out, netip.PrefixFrom(addrOf(lo, n), n-size))
		end := blockEnd(lo, size)
		if end.cmp(hi) >= 0 {
			return out
		}
		lo, _ = end.addOne()
	}
}

// trailingZeros128 returns the trailing zero bits of v, an address of n bits.
func trailingZeros128(v u128, n int) int {
	if v.lo != 0 {
		return bits.TrailingZeros64(v.lo)
	}
	if v.hi != 0 {
		return 64 + bits.TrailingZeros64(v.hi)
	}
	return n
}

// blockEnd returns the last address of the block of 2^size addresses at lo.
func blockEnd(lo u128, size int) u128 {
	m := hostMask128(128 - size)
	return u128{lo.hi | m.hi, lo.lo | m.lo}
}

func addrOf(v u128, n int) netip.Addr {
	if n == 32 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], v.hi)
	binary.BigEndian.PutUint64(b[8:], v.lo)
	return netip.AddrFrom16(b)
}
