package geomatch

import "strings"

// HostOf returns the host of addr, which may be a bare host or IP address,
// host:port, [IPv6]:port, or a URL such as https://user@host:443/path. The
// host is lowercased, without brackets, IPv6 zone or trailing dot. It
// returns "" if there is no host.
func HostOf(addr string) string {
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
