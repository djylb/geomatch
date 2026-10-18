package geomatch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"weak"
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
// GeoSiteList messages, for the rules of a Compiler. Opening a file indexes
// its entries by code, so a lookup reads only the entry it needs, and a file
// that changes on disk, or is replaced, is indexed again on the next lookup.
// A change is seen in the file's size, modification time or identity, so a
// file system without modification times, such as an embed.FS, is taken not
// to change in place with the same size.
//
// The entries compiled for rules are kept while a Matcher uses them, so that
// every Matcher compiled with the same GeoData shares them: many policies
// using geosite:cn hold it once, and entries that no Matcher uses any more
// go. Use one GeoData for the program, made by NewGeoData; SetFiles changes
// its files while it runs. The methods are safe for concurrent use. The zero
// GeoData has no files.
type GeoData struct {
	mu         sync.Mutex
	cfg        GeoFiles
	cfgGen     uint64 // counts SetFiles
	gen        uint64 // counts SetFiles and changes seen in files
	files      map[string]*datFile
	missing    map[string]bool      // files that did not exist, for Check
	siteCombos weakCache[domainSet] // merged entries by comboKey
	ipCombos   weakCache[ipSet]
}

// GeoFiles are the files of a GeoData.
type GeoFiles struct {
	// IP is the geoip.dat file of geoip: rules.
	IP string
	// Site is the geosite.dat file of geosite: rules.
	Site string
	// Dir is where relative file names of ext: rules are looked up. Empty
	// means the directory of the default file of the rule's kind, or of the
	// other default file, or with FS the root of FS. Without any of them,
	// relative names cannot be read, never relative to the working
	// directory.
	Dir string
	// FS, if set, holds the files, such as an embed.FS or an fs.FS of data
	// fetched at run time; the paths above are then slash-separated paths
	// in it. Nil reads the operating system's files.
	FS fs.FS
}

// NewGeoData returns a GeoData that reads files.
func NewGeoData(files GeoFiles) *GeoData {
	return &GeoData{cfg: files.trimmed()}
}

func (f GeoFiles) trimmed() GeoFiles {
	f.IP, f.Site, f.Dir = strings.TrimSpace(f.IP), strings.TrimSpace(f.Site), strings.TrimSpace(f.Dir)
	return f
}

// Files returns the files of g; a nil g has none.
func (g *GeoData) Files() GeoFiles {
	if g == nil {
		return GeoFiles{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg
}

// SetFiles replaces the files of g, such as when configuration changes
// while the program runs. Matchers already compiled keep their entries, and
// report Stale, so that a Live compiles its rules again from the new files.
func (g *GeoData) SetFiles(files GeoFiles) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg = files.trimmed()
	g.cfgGen++
	g.gen++
	g.files, g.missing, g.siteCombos, g.ipCombos = nil, nil, nil, nil
}

// Generation returns a number that grows whenever g sees its files change:
// SetFiles, a file indexed again because it changed, and changes that Check
// finds. A program with many Lives can call Check now and then, and Refresh
// them only when the generation grew.
func (g *GeoData) Generation() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen
}

// Check looks at the metadata of every file that g has read, or failed to
// find, and returns the generation, which grows if one changed or appeared.
func (g *GeoData) Check() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	v := g.viewLocked()
	type seen struct {
		name string
		f    *datFile
	}
	var files []seen
	for name, f := range g.files {
		files = append(files, seen{name, f})
	}
	var missing []string
	for name := range g.missing {
		missing = append(missing, name)
	}
	g.mu.Unlock()

	var changed []seen
	for _, s := range files {
		if fi, err := v.stat(s.name); err != nil || !sameVersion(s.f.info, fi) {
			changed = append(changed, s)
		}
	}
	var appeared []string
	for _, name := range missing {
		if _, err := v.stat(name); err == nil {
			appeared = append(appeared, name)
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfgGen != v.cfgGen {
		return g.gen // SetFiles counted already
	}
	bump := false
	for _, s := range changed {
		if g.files[s.name] == s.f {
			delete(g.files, s.name) // indexed again when next read
			bump = true
		}
	}
	for _, name := range appeared {
		if g.missing[name] {
			delete(g.missing, name)
			bump = true
		}
	}
	if bump {
		g.gen++
	}
	return g.gen
}

// maxMissing bounds the files that Check looks for after they did not
// exist, which rules can name without limit.
const maxMissing = 1024

// view is the files of a GeoData as one compile reads them, even if
// SetFiles changes them meanwhile.
type view struct {
	cfg    GeoFiles
	cfgGen uint64
}

func (g *GeoData) view() view {
	if g == nil {
		return view{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.viewLocked()
}

func (g *GeoData) viewLocked() view { return view{cfg: g.cfg, cfgGen: g.cfgGen} }

// geoIPSet is a compiled geoip entry.
type geoIPSet struct {
	set     *ipSet
	inverse bool // reverse_match
}

// Kinds of entry that load and compiled read.
const (
	kindIP = iota
	kindSite
	kindAny // whichever the record holds, for ext: rules
)

// LoadIP reads the entry for code, case-insensitive, of the geoip file at
// path file, or of the IP file when file is empty. Unlike the file of an
// ext-ip: rule, file is taken as given, not relative to Dir. The code
// PRIVATE falls back to the built-in private and special-use ranges when the
// file lacks it or cannot be read.
func (g *GeoData) LoadIP(file, code string) (GeoIP, error) {
	geo, _, _, err := g.load(file, func(f GeoFiles) string { return f.IP }, code, kindIP)
	if err != nil && strings.EqualFold(strings.TrimSpace(code), "private") {
		return GeoIP{Prefixes: slices.Clone(privatePrefixes)}, nil
	}
	return geo, err
}

// LoadSite reads the entries for code, case-insensitive, of the geosite file
// at path file, as given, or of the site file when file is empty.
func (g *GeoData) LoadSite(file, code string) ([]Domain, error) {
	_, domains, _, err := g.load(file, func(f GeoFiles) string { return f.Site }, code, kindSite)
	return domains, err
}

// IPCodes returns the codes of the geoip file at path file, as given, or of
// the IP file when file is empty, sorted and upper-case.
func (g *GeoData) IPCodes(file string) ([]string, error) {
	return g.codes(file, func(f GeoFiles) string { return f.IP })
}

// SiteCodes returns the codes of the geosite file at path file, as given, or
// of the site file when file is empty, sorted and upper-case: the categories
// that geosite: rules can name.
func (g *GeoData) SiteCodes(file string) ([]string, error) {
	return g.codes(file, func(f GeoFiles) string { return f.Site })
}

func (g *GeoData) codes(file string, def func(GeoFiles) string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := g.viewLocked()
	f, handle, _, err := g.openLocked(v, cmpOr(file, def(v.cfg)))
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
	g.files, g.missing, g.siteCombos, g.ipCombos = nil, nil, nil, nil
}

// extPath resolves the file name of an ext: rule: a relative name is looked
// up in Dir, or the directory of the default file of kind, or of the other
// default file, or with FS in its root.
func (v view) extPath(file string, kind int) (string, error) {
	join, dir, abs := filepath.Join, filepath.Dir, filepath.IsAbs(file)
	if v.cfg.FS != nil {
		join, dir, abs = path.Join, path.Dir, false
	}
	if abs {
		return file, nil
	}
	if base := v.extDir(dir, kind); base != "" {
		return join(base, file), nil
	}
	return "", fmt.Errorf("%w: no directory to find %s in; set GeoFiles.Dir", ErrNoGeoData, file)
}

// extDir returns the directory of relative ext: names of kind, or "".
func (v view) extDir(dir func(string) string, kind int) string {
	first, second := v.cfg.Site, v.cfg.IP
	if kind == kindIP {
		first, second = second, first
	}
	switch {
	case v.cfg.Dir != "":
		return v.cfg.Dir
	case first != "":
		return dir(first)
	case second != "":
		return dir(second)
	case v.cfg.FS != nil:
		return "."
	default:
		return ""
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

// load returns the entry for code of the file name, decoded as kind, and
// reports whether it is a geoip entry.
func (g *GeoData) load(file string, def func(GeoFiles) string, code string, kind int) (geo GeoIP, domains []Domain, isIP bool, err error) {
	code = upperASCII(strings.TrimSpace(code))
	g.mu.Lock()
	defer g.mu.Unlock()
	v := g.viewLocked()
	name := cmpOr(file, def(v.cfg))
	f, handle, _, err := g.openLocked(v, name)
	if err != nil {
		return GeoIP{}, nil, false, err
	}
	defer func() { _ = handle.Close() }()
	rec, err := f.read(handle, name, code)
	if err != nil {
		return GeoIP{}, nil, false, err
	}
	if isIP, err = resolveKind(name, code, recordKind(rec), kind); err != nil {
		return GeoIP{}, nil, false, err
	}
	geo, domains, err = decodeRecord(name, code, rec, isIP)
	return geo, domains, isIP, err
}

// compiledRule returns the compiled geo entry of a RuleGeoIP, RuleGeoSite or
// RuleExt rule, from the cache when another rule used it.
func (g *GeoData) compiledRule(v view, r Rule) (*geoIPSet, *domainSet, *source, error) {
	kind, name := kindAny, ""
	switch r.Kind {
	case RuleGeoIP:
		kind, name = kindIP, v.cfg.IP
	case RuleGeoSite:
		kind, name = kindSite, v.cfg.Site
	case RuleExt:
	case RuleIP, RuleFull, RuleDomain, RuleSubdomain, RuleKeyword, RuleRegexp, RuleDotless:
		return nil, nil, nil, fmt.Errorf("geomatch: %v reads no geodata", r)
	default:
		return nil, nil, nil, fmt.Errorf("geomatch: unknown rule kind %d", r.Kind)
	}
	if r.File != "" {
		var err error
		if name, err = v.extPath(r.File, kind); err != nil {
			if kind == kindIP && upperASCII(r.Code) == "PRIVATE" {
				return builtinPrivate(), nil, nil, nil
			}
			return nil, nil, nil, err
		}
	}
	geo, site, src, err := g.compiled(v, name, r.Code, r.Attrs, kind)
	switch {
	case err != nil:
		return nil, nil, src, err
	case geo != nil && len(r.Attrs) > 0:
		return nil, nil, src, errors.New("attributes on a geoip entry")
	case site != nil && r.Negate:
		return nil, nil, src, errors.New("! on a geosite entry")
	}
	return geo, site, src, nil
}

// compiled returns code of the file name compiled for rules, as kind,
// from the cache when another rule used it: a geoip entry, or a geosite
// entry restricted to the domains having every attribute in attrs, which are
// sorted. The code PRIVATE of a geoip file falls back to the built-in ranges.
//
// It also returns the file it read, for Matcher.Stale: with the version it
// read, or without one if the file did not exist.
func (g *GeoData) compiled(v view, name, code string, attrs []string, kind int) (*geoIPSet, *domainSet, *source, error) {
	name, code = strings.TrimSpace(name), upperASCII(strings.TrimSpace(code))
	key := strings.Join(append([]string{code}, attrs...), "@")
	g.mu.Lock()
	defer g.mu.Unlock()
	geo, site, info, err := g.compiledLocked(v, name, code, key, attrs, kind)
	var src *source
	if name != "" {
		src = &source{fsys: v.cfg.FS, name: name, info: info}
	}
	if err != nil && kind == kindIP && code == "PRIVATE" {
		return builtinPrivate(), nil, src, nil
	}
	return geo, site, src, err
}

func (g *GeoData) compiledLocked(v view, name, code, key string, attrs []string, kind int) (*geoIPSet, *domainSet, fs.FileInfo, error) {
	f, handle, fi, err := g.openLocked(v, name)
	if err != nil {
		return nil, nil, fi, err
	}
	defer func() { _ = handle.Close() }()
	k, known := f.kinds[code]
	var rec []byte
	if !known {
		if rec, err = f.read(handle, name, code); err != nil {
			return nil, nil, f.info, err
		}
		k = recordKind(rec)
		if f.kinds == nil {
			f.kinds = make(map[string]recKind)
		}
		f.kinds[code] = k
	}
	isIP, err := resolveKind(name, code, k, kind)
	if err != nil {
		return nil, nil, f.info, err
	}
	if s := f.ipSets.get(code); s != nil && isIP {
		return s, nil, f.info, nil
	}
	if s := f.siteSets.get(key); s != nil && !isIP {
		return nil, s, f.info, nil
	}
	if rec == nil {
		if rec, err = f.read(handle, name, code); err != nil {
			return nil, nil, f.info, err
		}
	}
	geo, domains, err := decodeRecord(name, code, rec, isIP)
	if err != nil {
		return nil, nil, f.info, err
	}
	if isIP {
		var b ipSetBuilder
		for _, p := range geo.Prefixes {
			b.addPrefix(p)
		}
		s := &geoIPSet{set: b.build(), inverse: geo.Inverse}
		f.ipSets.put(&g.mu, code, s)
		return s, nil, f.info, nil
	}
	d := &domainSet{}
	d.addDomains(filterAttrs(domains, attrs))
	d.finish()
	f.siteSets.put(&g.mu, key, d)
	return nil, d, f.info, nil
}

// mergedSites returns one set holding the domains of sets, built once for
// each combination, so that a Matcher with several geosite entries looks a
// host up once and Matchers with the same entries share the result.
func (g *GeoData) mergedSites(sets []*domainSet) *domainSet {
	return merged(g, &g.siteCombos, sets, mergeDomainSets)
}

// mergedIPs is mergedSites for geoip entries.
func (g *GeoData) mergedIPs(sets []*ipSet) *ipSet {
	return merged(g, &g.ipCombos, sets, mergeIPSets)
}

// merged returns merge(sets) from cache, building it once for each
// combination of sets regardless of their order. The cache holds it weakly:
// it goes when no Matcher uses it any more, so combinations that policies
// stop using do not accumulate. The sets do not change once built, so they
// are merged without holding the lock.
func merged[T any](g *GeoData, cache *weakCache[T], sets []*T, merge func([]*T) *T) *T {
	key := comboKey(sets)
	g.mu.Lock()
	s := cache.get(key)
	g.mu.Unlock()
	if s != nil {
		return s
	}
	s = merge(sets)
	g.mu.Lock()
	defer g.mu.Unlock()
	if prev := cache.get(key); prev != nil {
		return prev // merged meanwhile by another caller
	}
	cache.put(&g.mu, key, s)
	return s
}

// weakCache maps keys to values that it holds only while something else
// does, such as a Matcher, so that entries no longer used go away. Its
// methods are called with the lock of its GeoData held, which removing an
// entry takes.
type weakCache[T any] map[string]weak.Pointer[T]

// get returns the value of key, or nil.
func (c *weakCache[T]) get(key string) *T {
	return (*c)[key].Value()
}

// put sets the value of key and removes the entry, holding mu, once v is
// no longer used.
func (c *weakCache[T]) put(mu *sync.Mutex, key string, v *T) {
	if *c == nil {
		*c = make(weakCache[T])
	}
	wp := weak.Make(v)
	(*c)[key] = wp
	runtime.AddCleanup(v, func(key string) {
		mu.Lock()
		defer mu.Unlock()
		if (*c)[key] == wp {
			delete(*c, key)
		}
	}, key)
}

// comboKey identifies a combination of compiled entries regardless of order.
func comboKey[T any](sets []*T) string {
	parts := make([]string, len(sets))
	for i, s := range sets {
		parts[i] = fmt.Sprintf("%p", s)
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// openLocked opens name of the files v and returns its index, which it
// builds from the open handle on first use and whenever the file is no
// longer the one indexed. The caller closes the handle. It also returns the
// file's stat, even with an error if the file exists, for Matcher.Stale.
// Indexes are kept only while v has the current files.
func (g *GeoData) openLocked(v view, name string) (*datFile, geoFile, fs.FileInfo, error) {
	if name == "" {
		return nil, nil, nil, ErrNoGeoData
	}
	current := v.cfgGen == g.cfgGen
	var file fs.File
	var err error
	if v.cfg.FS != nil {
		file, err = v.cfg.FS.Open(fsPath(name))
	} else {
		file, err = os.Open(name)
	}
	if err != nil {
		fi, _ := v.stat(name) // a file that exists but cannot be opened
		if fi == nil && current && len(g.missing) < maxMissing {
			if g.missing == nil {
				g.missing = make(map[string]bool)
			}
			g.missing[name] = true
		}
		return nil, nil, fi, err
	}
	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, nil, err
	}
	handle, readAt := file.(geoFile)
	prev, cached := g.files[name]
	if cached && current && sameVersion(prev.info, fi) {
		if readAt {
			return prev, handle, fi, nil
		}
		_ = file.Close()
		return prev, nopCloser{bytes.NewReader(prev.data)}, fi, nil
	}
	// A file without ReadAt is read into memory and kept with its index.
	size, data := fi.Size(), []byte(nil)
	if !readAt {
		data, err = io.ReadAll(file)
		_ = file.Close()
		if err != nil {
			return nil, nil, fi, err
		}
		size, handle = int64(len(data)), nopCloser{bytes.NewReader(data)}
	}
	index, err := indexDat(handle, size)
	if err != nil {
		_ = handle.Close()
		return nil, nil, fi, fmt.Errorf("%w: %s", err, name)
	}
	f := &datFile{info: fi, index: index, data: data}
	if !current {
		return f, handle, fi, nil
	}
	if g.files == nil {
		g.files = make(map[string]*datFile)
	}
	g.files[name] = f
	delete(g.missing, name)
	if cached {
		g.gen++ // a file that changed
		// Merged entries may hold entries of the previous version.
		g.siteCombos, g.ipCombos = nil, nil
	}
	return f, handle, fi, nil
}

// stat returns the stat of the file name of v.
func (v view) stat(name string) (fs.FileInfo, error) {
	return statIn(v.cfg.FS, name)
}

// statIn returns the stat of the file name of fsys, or of the operating
// system if fsys is nil.
func statIn(fsys fs.FS, name string) (fs.FileInfo, error) {
	if fsys != nil {
		return fs.Stat(fsys, fsPath(name))
	}
	return os.Stat(name)
}

// fsPath returns name as a path of GeoFiles.FS.
func fsPath(name string) string {
	return path.Clean(filepath.ToSlash(name))
}

var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
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

// filterAttrs returns the domains that have every attribute in attrs.
func filterAttrs(domains []Domain, attrs []string) []Domain {
	if len(attrs) == 0 {
		return domains
	}
	var out []Domain
next:
	for _, d := range domains {
		for _, a := range attrs {
			if !slices.Contains(d.Attrs, a) {
				continue next
			}
		}
		out = append(out, d)
	}
	return out
}

// Source is a geodata file that a Matcher was compiled from.
type Source struct {
	File string
	// Missing reports that the file did not exist, so that the rules
	// needing it were skipped.
	Missing bool
	Size    int64
	ModTime time.Time
}

// source is a file read for a Matcher, with the version read, or a nil info
// if it did not exist.
type source struct {
	fsys fs.FS
	name string
	info fs.FileInfo
}

// export returns s as a Source.
func (s source) export() Source {
	if s.info == nil {
		return Source{File: s.name, Missing: true}
	}
	return Source{File: s.name, Size: s.info.Size(), ModTime: s.info.ModTime()}
}

// changed reports whether the file named by s is no longer the version
// read, or exists after it did not.
func (s source) changed() bool {
	fi, err := statIn(s.fsys, s.name)
	if s.info == nil {
		return err == nil
	}
	return err != nil || !sameVersion(s.info, fi)
}
