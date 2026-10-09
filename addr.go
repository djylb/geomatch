package geomatch

import "strings"

// HostOf returns the host of addr, which may be a bare host or IP address,
// host:port, [IPv6]:port, or a URL such as https://user@host:443/path. The
// host is lowercased, without brackets, IPv6 zone or trailing dot. It
// returns "" if there is no host.
func HostOf(addr string) string {
	if plain, _ := hostClass(addr); plain {
		return addr
	}
	s := strings.TrimSpace(addr)
	// A scheme ends before the first /, ? or #; a :// later on belongs to
	// a path or query, such as a redirect target.
	if i := strings.Index(s, "://"); i >= 0 && !strings.ContainsAny(s[:i], "/?#") {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	ipv6 := false
	if strings.HasPrefix(s, "[") {
		i := strings.IndexByte(s, ']')
		if i < 0 {
			return ""
		}
		s, ipv6 = s[1:i], true
	} else if i := strings.IndexByte(s, ':'); i >= 0 {
		if strings.LastIndexByte(s, ':') == i {
			s = s[:i] // host:port
		} else {
			ipv6 = true // a bare IPv6 address has several colons
		}
	}
	if i := strings.LastIndexByte(s, '%'); i >= 0 && ipv6 {
		s = s[:i] // zone
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// hostClass scans s once. plain reports whether s is already a normalized
// host name or IPv4 address, the common case, which HostOf returns unchanged;
// numeric whether it holds only digits and dots, so may be an IPv4 address.
func hostClass(s string) (plain, numeric bool) {
	if s == "" || s[len(s)-1] == '.' {
		return false, false
	}
	numeric = true
	for i := range len(s) {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c == '.':
		case c >= 'a' && c <= 'z', c == '-', c == '_':
			numeric = false
		default:
			return false, false
		}
	}
	return true, numeric
}
