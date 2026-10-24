package geomatch

import (
	"net"
	"net/netip"
	"strings"
)

// HostOf returns the host of addr, which may be a bare host or IP address,
// host:port, [IPv6]:port, or a URL such as https://user@host:443/path or a
// scheme-relative //host/path. The host is lowercased, without brackets,
// IPv6 zone or trailing dot, with internationalized labels in their xn--
// form. It returns "" if there is no host. A backslash ends the host, as
// browsers read it as a slash.
//
// Match reads a host in the legacy forms of IPv4 that system resolvers
// accept, such as 127.1, 2130706433 or 0x7f.0.0.1, as the IPv4 address it
// stands for, so that IP rules see the address a program would connect to.
func HostOf(addr string) string {
	if isPlainHost(addr) {
		return addr
	}
	s := strings.TrimSpace(addr)
	// A scheme ends before the first /, ? or #; a :// later on belongs to
	// a path or query, such as a redirect target.
	if i := strings.Index(s, "://"); i >= 0 && !strings.ContainsAny(s[:i], "/?#\\") {
		s = s[i+3:]
	} else if rest, ok := strings.CutPrefix(s, "//"); ok {
		s = rest // a scheme-relative URL
	}
	// Browsers read a backslash as a slash, so http://a.com\@b.com/ goes
	// to a.com: the host ends there as well.
	if i := strings.IndexAny(s, "/?#\\"); i >= 0 {
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
	host, _ := normalHost(s) // "" for invalid UTF-8: no host
	return host
}

// isPlainHost reports whether s is already a normalized host name or IPv4
// address, the common case, which HostOf returns unchanged.
func isPlainHost(s string) bool {
	if s == "" || s[len(s)-1] == '.' {
		return false
	}
	for i := range len(s) {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c == '.', c >= 'a' && c <= 'z', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// target is what a query matches: an IP address, unmapped and without a
// zone, and a normalized host name. Either may be missing; the zero target
// matches nothing.
type target struct {
	host string
	ip   netip.Addr
}

// addrTarget reads the host of addr, as its IP address if it is one.
func addrTarget(addr string) target {
	host := HostOf(addr)
	if ip, ok := hostIP(host); ok {
		return target{ip: ip}
	}
	return target{host: host}
}

// hostIP parses host, as HostOf returns it, as an IP address: a host with a
// colon as netip.ParseAddr reads it, and others in the forms of IPv4 that
// legacyIPv4 reads, dotted decimal among them. It allocates only for a host
// with a colon that is no address, for the error of netip.ParseAddr. The
// address is unmapped and without a zone.
func hostIP(host string) (netip.Addr, bool) {
	if strings.IndexByte(host, ':') < 0 {
		return legacyIPv4(host)
	}
	ip, err := netip.ParseAddr(host)
	return normalAddr(ip), err == nil
}

// normalAddr returns ip as queries and rules match it: an IPv4-mapped
// address as IPv4, without a zone.
func normalAddr(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

// legacyIPv4 parses host as inet_aton does, which system resolvers use for
// numeric hosts: one to four parts, each decimal, octal with a leading 0 or
// hexadecimal with 0x, the last filling the remaining bytes, as in 127.1,
// 2130706433 or 0x7f.0.0.1, and the dotted decimal form that netip.ParseAddr
// reads.
func legacyIPv4(host string) (netip.Addr, bool) {
	if host == "" || host[0] < '0' || host[0] > '9' {
		return netip.Addr{}, false
	}
	var parts [4]uint64
	n := 0
	for part := range strings.SplitSeq(host, ".") {
		if n == len(parts) {
			return netip.Addr{}, false
		}
		v, ok := legacyNumber(part)
		if !ok {
			return netip.Addr{}, false
		}
		parts[n] = v
		n++
	}
	// The last part fills the bytes that the others leave.
	limits := [4]uint64{1<<32 - 1, 1<<24 - 1, 1<<16 - 1, 1<<8 - 1}
	var v uint64
	for i := range n - 1 {
		if parts[i] > 0xff {
			return netip.Addr{}, false
		}
		v |= parts[i] << (24 - 8*i)
	}
	if parts[n-1] > limits[n-1] {
		return netip.Addr{}, false
	}
	v |= parts[n-1]
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// legacyNumber parses one part of a legacy IPv4 address.
func legacyNumber(s string) (uint64, bool) {
	base := 10
	switch {
	case s == "":
		return 0, false
	case len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'):
		s, base = s[2:], 16
		if s == "" {
			return 0, true // inet_aton reads a bare 0x as 0
		}
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	var v uint64
	for i := range len(s) {
		d := uint64(16)
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		}
		if d >= uint64(base) {
			return 0, false
		}
		if v = v*uint64(base) + d; v > 1<<32-1 {
			return 0, false
		}
	}
	return v, true
}

func ipTarget(ip netip.Addr) target {
	return target{ip: normalAddr(ip)}
}

// domainTarget reads host as a domain name only: an IP address, also in a
// legacy form, is no target.
func domainTarget(host string) target {
	host = HostOf(host)
	if _, ok := hostIP(host); ok {
		return target{}
	}
	return target{host: host}
}

// hostIPTarget reads a domain name and an IP address, such as the one it
// resolved to; either may be missing.
func hostIPTarget(host string, ip netip.Addr) target {
	t := domainTarget(host)
	t.ip = normalAddr(ip)
	return t
}

// netAddrTarget reads the IP address of an IP net.Addr, and the String of
// other addresses but Unix sockets.
func netAddrTarget(a net.Addr) target {
	switch a := a.(type) {
	case nil, *net.UnixAddr:
		return target{}
	case *net.TCPAddr:
		return ipTarget(a.AddrPort().Addr())
	case *net.UDPAddr:
		return ipTarget(a.AddrPort().Addr())
	case *net.IPAddr:
		if a == nil {
			return target{}
		}
		ip, _ := netip.AddrFromSlice(a.IP)
		return ipTarget(ip)
	}
	return addrTarget(a.String())
}
