package geomatch

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalHost returns host in the form that rules and queries match in:
// lowercase, with the full-width dots that IDNA reads as dots as dots,
// without a trailing dot, and with every label that holds non-ASCII
// characters in its xn-- form, as names travel in TLS and DNS and as geosite
// files hold them. It reports false for a host that cannot be encoded, such
// as one with invalid UTF-8. Names that need the mappings of IDNA beyond
// lowercasing are best written in their xn-- form.
func normalHost(host string) (string, bool) {
	if isASCII(host) {
		return strings.ToLower(strings.TrimSuffix(host, ".")), true
	}
	if !utf8.ValidString(host) {
		return "", false
	}
	return asciiHost(foldHost(host))
}

// foldHost returns host, which must be valid UTF-8, lowercase, with
// full-width dots as dots and without a trailing dot: normalHost without the
// xn-- form, for rules that check what was written before encoding it.
func foldHost(host string) string {
	if isASCII(host) {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return strings.TrimSuffix(strings.Map(foldRune, host), ".")
}

// foldRune lowercases r, as strings.ToLower does, and reads the ideographic
// and full-width full stops as dots.
func foldRune(r rune) rune {
	switch r {
	case '。', '．', '｡':
		return '.'
	}
	return unicode.ToLower(r)
}

// asciiHost returns host, which foldHost returned, with every label that
// holds non-ASCII characters in its IDNA ASCII form, "xn--" and the punycode
// of the label. It reports false for a label that cannot be encoded.
func asciiHost(host string) (string, bool) {
	if isASCII(host) {
		return host, true
	}
	var b strings.Builder
	b.Grow(len(host) + 8)
	for rest, more := host, true; more; {
		var label string
		label, rest, more = strings.Cut(rest, ".")
		if isASCII(label) {
			b.WriteString(label)
		} else {
			b.WriteString("xn--")
			if !writePunycode(&b, label) {
				return "", false
			}
		}
		if more {
			b.WriteByte('.')
		}
	}
	return b.String(), true
}

// Parameters of punycode, RFC 3492 section 5.
const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
	punyMaxDelta    = 1 << 30 // far above what a host label of 63 bytes needs
)

// writePunycode writes the punycode of label, which must be valid UTF-8, to
// b, as RFC 3492 section 6.3 encodes it. It reports false if the label is
// too long to encode, leaving b partly written.
func writePunycode(b *strings.Builder, label string) bool {
	basic := 0
	for _, r := range label {
		if r < utf8.RuneSelf {
			b.WriteByte(byte(r))
			basic++
		}
	}
	runes := utf8.RuneCountInString(label)
	handled := basic
	if basic > 0 {
		b.WriteByte('-')
	}
	n, delta, bias := rune(punyInitialN), 0, punyInitialBias
	for handled < runes {
		next := utf8.MaxRune + 1
		for _, r := range label {
			if r >= n && r < next {
				next = r
			}
		}
		delta += int(next-n) * (handled + 1)
		if delta > punyMaxDelta {
			return false
		}
		n = next
		for _, r := range label {
			if r < n {
				if delta++; delta > punyMaxDelta {
					return false
				}
				continue
			}
			if r != n {
				continue
			}
			q := delta
			for k := punyBase; ; k += punyBase {
				t := min(max(k-bias, punyTMin), punyTMax)
				if q < t {
					break
				}
				b.WriteByte(punyDigit(t + (q-t)%(punyBase-t)))
				q = (q - t) / (punyBase - t)
			}
			b.WriteByte(punyDigit(q))
			bias = punyAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return true
}

func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func punyAdapt(delta, points int, first bool) int {
	if first {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}
