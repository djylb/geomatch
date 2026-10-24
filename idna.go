package geomatch

import (
	"strings"
	"unicode/utf8"
)

// asciiHost returns host, lowercase, with every label that holds non-ASCII
// characters in its IDNA ASCII form, "xn--" and the punycode of the label, as
// names travel in TLS and DNS and as geosite files hold them. It reports
// false for a label that cannot be encoded, such as one with invalid UTF-8.
// Names that need the mappings of IDNA beyond lowercasing are best written in
// their xn-- form.
func asciiHost(host string) (string, bool) {
	if isASCII(host) {
		return host, true
	}
	if !utf8.ValidString(host) {
		return "", false
	}
	labels := strings.Split(strings.ToLower(fullWidthDots(host)), ".")
	for i, label := range labels {
		if isASCII(label) {
			continue
		}
		encoded, ok := punycode(label)
		if !ok {
			return "", false
		}
		labels[i] = "xn--" + encoded
	}
	return strings.Join(labels, "."), true
}

// fullWidthDots replaces the ideographic and full-width full stops, which
// IDNA reads as dots, with dots.
func fullWidthDots(s string) string {
	if isASCII(s) {
		return s
	}
	return strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(s)
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

// punycode encodes label as RFC 3492 section 6.3 does.
func punycode(label string) (string, bool) {
	if !utf8.ValidString(label) {
		return "", false
	}
	runes := []rune(label)
	out := make([]byte, 0, len(label)+8)
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(punyInitialN), 0, punyInitialBias
	for handled < len(runes) {
		next := utf8.MaxRune + 1
		for _, r := range runes {
			if r >= n && r < next {
				next = r
			}
		}
		delta += int(next-n) * (handled + 1)
		if delta > punyMaxDelta {
			return "", false
		}
		n = next
		for _, r := range runes {
			if r < n {
				if delta++; delta > punyMaxDelta {
					return "", false
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
				out = append(out, punyDigit(t+(q-t)%(punyBase-t)))
				q = (q - t) / (punyBase - t)
			}
			out = append(out, punyDigit(q))
			bias = punyAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return string(out), true
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
