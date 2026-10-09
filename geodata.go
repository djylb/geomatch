package geomatch

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

var (
	// ErrNoGeoData is returned for a geoip: or geosite: lookup when no file is
	// configured for it.
	ErrNoGeoData = errors.New("geomatch: no geodata file configured")
	// ErrCodeNotFound is returned when a geodata file has no entry for a code.
	ErrCodeNotFound = errors.New("geomatch: code not found in geodata file")
)

// DomainType is the kind of a geosite entry.
type DomainType uint8

// Geosite entry kinds.
const (
	DomainKeyword DomainType = 0 // the value is a substring of the host
	DomainRegexp  DomainType = 1 // the value is a regular expression
	DomainRoot    DomainType = 2 // the host is the value or a subdomain of it
	DomainFull    DomainType = 3 // the host is exactly the value
)

// Domain is a geosite entry.
type Domain struct {
	Type DomainType
	// Value is lowercase, except for regular expressions, which match
	// regardless of case.
	Value string
	// Attrs are the lowercase attribute keys, such as "cn" or "ads", that
	// geosite:code@attr rules select by.
	Attrs []string
}

// GeoIP is a geoip entry.
type GeoIP struct {
	Prefixes []netip.Prefix
	// Inverse marks an entry that matches the addresses outside Prefixes
	// (reverse_match in the file).
	Inverse bool
}

// GeoData reads geoip.dat and geosite.dat files, protobuf GeoIPList and
// GeoSiteList messages. Opening a file indexes its entries by code, so a
// lookup reads only the entry it needs, and a file that changes on disk, or
// is replaced, is indexed again on the next lookup. The entries compiled for
// rules are kept, so that every Matcher compiled with the same GeoData shares
// them: many policies using geosite:cn hold it once. The methods are safe for
// concurrent use. The zero value has no default files, so only ext: rules
// read files, relative to the working directory.
type GeoData struct {
	// IPFile is the geoip.dat file of geoip: rules.
	IPFile string
	// SiteFile is the geosite.dat file of geosite: rules.
	SiteFile string
	// Dir is where relative file names of ext: rules are looked up; empty
	// means the directory of SiteFile, or of IPFile, for the rule's kind.
	Dir string

	mu     sync.Mutex
	files  map[string]*datFile
	combos map[string]any // merged *domainSet and *ipSet by comboKey
}

// datFile is the index of one version of a file and the entries compiled
// from it, which every Matcher compiled with the GeoData shares.
type datFile struct {
	info     os.FileInfo
	index    map[string]span    // by upper-case code
	kinds    map[string]recKind // of the codes read so far
	ipSets   map[string]*geoIPSet
	siteSets map[string]*domainSet // by code and attributes
}

// geoIPSet is a compiled geoip entry.
type geoIPSet struct {
	set     *ipSet
	inverse bool // reverse_match
}

type span struct{ off, n int64 }

// Kinds of entry that load and compiled read.
const (
	kindIP = iota
	kindSite
	kindAny // whichever the record holds, for ext: rules
)

// LoadIP reads the entry for code, case-insensitive, of the geoip file at
// path file, or of IPFile when file is empty. The code PRIVATE falls back to
// the built-in private and special-use ranges when the file lacks it or
// cannot be read.
func (g *GeoData) LoadIP(file, code string) (GeoIP, error) {
	geo, _, _, err := g.load(cmpOr(file, g.IPFile), code, kindIP)
	if err != nil && strings.EqualFold(strings.TrimSpace(code), "private") {
		return GeoIP{Prefixes: slices.Clone(privatePrefixes)}, nil
	}
	return geo, err
}

// LoadSite reads the entries for code, case-insensitive, of the geosite file
// at path file, or of SiteFile when file is empty.
func (g *GeoData) LoadSite(file, code string) ([]Domain, error) {
	_, domains, _, err := g.load(cmpOr(file, g.SiteFile), code, kindSite)
	return domains, err
}

// Codes returns the codes of the geodata file at path file, sorted; an empty
// file means SiteFile, or IPFile if SiteFile is empty.
func (g *GeoData) Codes(file string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, handle, err := g.openLocked(cmpOr(file, g.SiteFile, g.IPFile))
	if err != nil {
		return nil, err
	}
	_ = handle.Close()
	codes := make([]string, 0, len(f.index))
	for code := range f.index {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes, nil
}

// Reset drops the indexes and compiled entries; Matchers already compiled
// keep theirs.
func (g *GeoData) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files, g.combos = nil, nil
}

// rulePath resolves the file name of an ext: rule: a relative name is looked
// up in Dir or the directory of def.
func (g *GeoData) rulePath(file, def string) string {
	def = strings.TrimSpace(def)
	switch {
	case filepath.IsAbs(file):
		return file
	case g.Dir != "":
		return filepath.Join(g.Dir, file)
	case def != "":
		return filepath.Join(filepath.Dir(def), file)
	default:
		return file
	}
}

func cmpOr(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// load returns the entry for code of the file at path, decoded as kind, and
// reports whether it is a geoip entry.
func (g *GeoData) load(path, code string, kind int) (geo GeoIP, domains []Domain, isIP bool, err error) {
	path, code = strings.TrimSpace(path), strings.ToUpper(strings.TrimSpace(code))
	g.mu.Lock()
	defer g.mu.Unlock()
	f, handle, err := g.openLocked(path)
	if err != nil {
		return GeoIP{}, nil, false, err
	}
	defer func() { _ = handle.Close() }()
	rec, err := f.read(handle, path, code)
	if err != nil {
		return GeoIP{}, nil, false, err
	}
	if isIP, err = resolveKind(path, code, recordKind(rec), kind); err != nil {
		return GeoIP{}, nil, false, err
	}
	geo, domains, err = decodeRecord(path, code, rec, isIP)
	return geo, domains, isIP, err
}

// read returns the raw record of code, read from handle, which was checked
// against, or produced, the index, so that a file replaced meanwhile cannot
// mix them up.
func (f *datFile) read(handle *os.File, path, code string) ([]byte, error) {
	if code == "" {
		return nil, errors.New("geomatch: empty geodata code")
	}
	sp, ok := f.index[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s in %s", ErrCodeNotFound, code, path)
	}
	rec := make([]byte, sp.n)
	if _, err := handle.ReadAt(rec, sp.off); err != nil {
		return nil, err
	}
	return rec, nil
}

// recKind is what a record holds: a geoip entry, or a geosite one, which
// is known for certain unless the record has no entries.
type recKind struct {
	isIP, certain bool
}

// resolveKind decides how to read a record of kind k for a rule of kind:
// as a geoip entry or a geosite one, or not at all if the rule names the
// other kind.
func resolveKind(path, code string, k recKind, kind int) (isIP bool, err error) {
	switch {
	case kind == kindIP && k.certain && !k.isIP:
		return false, fmt.Errorf("geomatch: %s in %s is a geosite entry", code, path)
	case kind == kindSite && k.certain && k.isIP:
		return false, fmt.Errorf("geomatch: %s in %s is a geoip entry", code, path)
	case kind == kindAny:
		return k.isIP, nil
	default:
		return kind == kindIP, nil
	}
}

func decodeRecord(path, code string, rec []byte, isIP bool) (geo GeoIP, domains []Domain, err error) {
	if isIP {
		geo, err = decodeGeoIP(rec)
	} else {
		domains, err = decodeGeoSite(rec)
	}
	if err != nil {
		return GeoIP{}, nil, fmt.Errorf("%w: %s in %s", err, code, path)
	}
	return geo, domains, nil
}

// compiled returns code of the file at path compiled for rules, as kind,
// from the cache when another rule used it: a geoip entry, or a geosite
// entry restricted to the domains having every attribute in attrs. The
// code PRIVATE of a geoip file falls back to the built-in ranges.
func (g *GeoData) compiled(path, code string, attrs []string, kind int) (*geoIPSet, *domainSet, error) {
	path, code = strings.TrimSpace(path), strings.ToUpper(strings.TrimSpace(code))
	slices.Sort(attrs)
	key := strings.Join(append([]string{code}, attrs...), "@")
	g.mu.Lock()
	defer g.mu.Unlock()
	geo, site, err := g.compiledLocked(path, code, key, attrs, kind)
	if err != nil && kind == kindIP && code == "PRIVATE" {
		return builtinPrivate(), nil, nil
	}
	return geo, site, err
}

func (g *GeoData) compiledLocked(path, code, key string, attrs []string, kind int) (*geoIPSet, *domainSet, error) {
	f, handle, err := g.openLocked(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = handle.Close() }()
	k, known := f.kinds[code]
	var rec []byte
	if !known {
		if rec, err = f.read(handle, path, code); err != nil {
			return nil, nil, err
		}
		k = recordKind(rec)
		if f.kinds == nil {
			f.kinds = make(map[string]recKind)
		}
		f.kinds[code] = k
	}
	isIP, err := resolveKind(path, code, k, kind)
	if err != nil {
		return nil, nil, err
	}
	if s, ok := f.ipSets[code]; ok && isIP {
		return s, nil, nil
	}
	if s, ok := f.siteSets[key]; ok && !isIP {
		return nil, s, nil
	}
	if rec == nil {
		if rec, err = f.read(handle, path, code); err != nil {
			return nil, nil, err
		}
	}
	geo, domains, err := decodeRecord(path, code, rec, isIP)
	if err != nil {
		return nil, nil, err
	}
	if isIP {
		var b ipSetBuilder
		for _, p := range geo.Prefixes {
			b.addPrefix(p)
		}
		s := &geoIPSet{set: b.build(), inverse: geo.Inverse}
		if f.ipSets == nil {
			f.ipSets = make(map[string]*geoIPSet)
		}
		f.ipSets[code] = s
		return s, nil, nil
	}
	d := &domainSet{}
	d.addDomains(filterAttrs(domains, attrs))
	d.finish()
	if f.siteSets == nil {
		f.siteSets = make(map[string]*domainSet)
	}
	f.siteSets[key] = d
	return nil, d, nil
}

// mergedSites returns one set holding the domains of sets, built once for
// each combination, so that a Matcher with several geosite entries looks a
// host up once and Matchers with the same entries share the result.
func (g *GeoData) mergedSites(sets []*domainSet) *domainSet {
	key := comboKey("site", sets)
	g.mu.Lock()
	defer g.mu.Unlock()
	if d, ok := g.combos[key].(*domainSet); ok {
		return d
	}
	d := mergeDomainSets(sets)
	g.storeComboLocked(key, d)
	return d
}

// mergedIPs is mergedSites for geoip entries.
func (g *GeoData) mergedIPs(sets []*ipSet) *ipSet {
	key := comboKey("ip", sets)
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.combos[key].(*ipSet); ok {
		return s
	}
	s := mergeIPSets(sets)
	g.storeComboLocked(key, s)
	return s
}

func (g *GeoData) storeComboLocked(key string, set any) {
	if g.combos == nil {
		g.combos = make(map[string]any)
	}
	g.combos[key] = set
}

// comboKey identifies a combination of compiled entries regardless of order.
func comboKey[T any](kind string, sets []*T) string {
	parts := make([]string, len(sets))
	for i, s := range sets {
		parts[i] = fmt.Sprintf("%p", s)
	}
	slices.Sort(parts)
	return kind + ":" + strings.Join(parts, ",")
}

// openLocked opens path and returns its index, which it builds from the open
// handle on first use and whenever the file is no longer the one indexed.
// The caller closes the handle.
func (g *GeoData) openLocked(path string) (*datFile, *os.File, error) {
	if path == "" {
		return nil, nil, ErrNoGeoData
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, nil, err
	}
	if f, ok := g.files[path]; ok && os.SameFile(f.info, fi) && f.info.Size() == fi.Size() && f.info.ModTime().Equal(fi.ModTime()) {
		return f, handle, nil
	}
	index, err := indexDat(handle, fi.Size())
	if err != nil {
		_ = handle.Close()
		return nil, nil, fmt.Errorf("%w: %s", err, path)
	}
	f := &datFile{info: fi, index: index}
	if g.files == nil {
		g.files = make(map[string]*datFile)
	}
	g.files[path] = f
	g.combos = nil // they may hold entries of the previous version
	return f, handle, nil
}

// indexDat indexes a GeoIPList or GeoSiteList: a sequence of field 1
// messages, each holding its code in field 1. Other fields are skipped, and
// the first of several entries with one code wins. It reads the
// start of every entry, and the whole entry only when its code is not there.
func indexDat(r io.ReaderAt, size int64) (map[string]span, error) {
	index := make(map[string]span)
	buf := make([]byte, 512)
	for off := int64(0); off < size; {
		n, err := r.ReadAt(buf, off)
		if n == 0 {
			if err == nil || err == io.EOF {
				err = errProto
			}
			return nil, err
		}
		head := protoReader{b: buf[:n]}
		num, typ, ok := head.next()
		if !ok {
			return nil, errProto
		}
		if typ != wireBytes {
			head.skip(typ)
			if head.err != nil {
				return nil, errProto
			}
			off += int64(n - len(head.b))
			continue
		}
		length := head.varint()
		if head.err != nil || length > maxRecord {
			return nil, errProto
		}
		body := off + int64(n-len(head.b))
		if body+int64(length) > size {
			return nil, errProto
		}
		if num == 1 {
			code, err := recordCode(r, body, int64(length), head.b)
			if err != nil {
				return nil, err
			}
			if key := strings.ToUpper(code); key != "" {
				if _, dup := index[key]; !dup {
					index[key] = span{body, int64(length)}
				}
			}
		}
		off = body + int64(length)
	}
	return index, nil
}

// recordCode returns the code of the n-byte record at off, whose first bytes
// are in head.
func recordCode(r io.ReaderAt, off, n int64, head []byte) (string, error) {
	head = head[:min(int64(len(head)), n)]
	if code, ok := fieldBytes(head, 1); ok {
		return string(code), nil
	}
	if int64(len(head)) == n {
		return "", nil // a record without a code
	}
	rec := make([]byte, n)
	if _, err := r.ReadAt(rec, off); err != nil {
		return "", err
	}
	code, _ := fieldBytes(rec, 1)
	return string(code), nil
}

// decodeGeoIP decodes a GeoIP message: code (1), CIDRs (2) and reverse_match
// (3). Each CIDR holds the address bytes (1) and the prefix length (2);
// invalid ones are left out.
func decodeGeoIP(rec []byte) (GeoIP, error) {
	var geo GeoIP
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 2 && typ == wireBytes:
			if p, ok := decodeCIDR(r.bytes()); ok {
				geo.Prefixes = append(geo.Prefixes, p)
			}
		case num == 3 && typ == wireVarint:
			geo.Inverse = r.varint() != 0
		default:
			r.skip(typ)
		}
	}
	return geo, r.err
}

func decodeCIDR(msg []byte) (netip.Prefix, bool) {
	var ip []byte
	var bits uint64
	r := protoReader{b: msg}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 1 && typ == wireBytes:
			ip = r.bytes()
		case num == 2 && typ == wireVarint:
			bits = r.varint()
		default:
			r.skip(typ)
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if r.err != nil || !ok || bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, int(bits)).Masked(), true
}

// decodeGeoSite decodes a GeoSite message: code (1) and domains (2). Each
// domain holds its type (1), value (2) and attributes (3), whose key is
// field 1; unknown types and empty values are left out.
func decodeGeoSite(rec []byte) ([]Domain, error) {
	var domains []Domain
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		if num != 2 || typ != wireBytes {
			r.skip(typ)
			continue
		}
		if d, ok := decodeDomain(r.bytes()); ok {
			domains = append(domains, d)
		}
	}
	return domains, r.err
}

func decodeDomain(msg []byte) (Domain, bool) {
	var d Domain
	var value []byte
	r := protoReader{b: msg}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 1 && typ == wireVarint:
			t := r.varint()
			if t > uint64(DomainFull) {
				return Domain{}, false
			}
			d.Type = DomainType(t)
		case num == 2 && typ == wireBytes:
			value = r.bytes()
		case num == 3 && typ == wireBytes:
			if key, ok := fieldBytes(r.bytes(), 1); ok && len(key) > 0 {
				d.Attrs = append(d.Attrs, strings.ToLower(string(key)))
			}
		default:
			r.skip(typ)
		}
	}
	d.Value = strings.TrimSpace(string(value))
	if r.err != nil || d.Value == "" {
		return Domain{}, false
	}
	if d.Type != DomainRegexp {
		d.Value = strings.TrimSuffix(strings.ToLower(d.Value), ".")
	}
	return d, true
}

// recordKind tells which format a record has: geoip if it has reverse_match
// (field 3) or its first entry in field 2 is a CIDR, starting with its
// address bytes, rather than a domain, starting with its type (a varint) or,
// when the type is zero and omitted, its value in field 2. A record without
// entries is taken for geoip, where it can match through !, but uncertainly.
func recordKind(rec []byte) recKind {
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			return recKind{isIP: true}
		}
		switch {
		case num == 3 && typ == wireVarint:
			return recKind{isIP: true, certain: true}
		case num == 2 && typ == wireBytes:
			inner := protoReader{b: r.bytes()}
			n, t, ok := inner.next()
			if !ok {
				continue
			}
			return recKind{isIP: n == 1 && t == wireBytes || n == 2 && t == wireVarint, certain: true}
		default:
			r.skip(typ)
		}
	}
}

// privatePrefixes are the private and special-use ranges that the PRIVATE
// code stands for, used when no geoip file provides it.
var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// builtinPrivate is the compiled form of privatePrefixes.
var builtinPrivate = sync.OnceValue(func() *geoIPSet {
	var b ipSetBuilder
	for _, p := range privatePrefixes {
		b.addPrefix(p)
	}
	return &geoIPSet{set: b.build()}
})
