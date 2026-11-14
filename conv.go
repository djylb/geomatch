package geomatch

// nonNeg converts n, which the caller knows not to be negative, to a uint64.
func nonNeg(n int) uint64 {
	return uint64(n) //nolint:gosec // n >= 0 by the caller's contract
}

// The words of rule kinds and policy modes that the parsers and the printers
// share.
const (
	textExt       = "ext"
	textExtIP     = "ext-ip"
	textExtDomain = "ext-domain"
	textGeoIP     = "geoip"
	textRegexp    = "regexp"
	textFull      = "full"
	textKeyword   = "keyword"
	textGeoSite   = "geosite"
	textDomain    = "domain"
	textDotless   = "dotless"
	textAllowlist = "allowlist"
	textDenylist  = "denylist"
)
