package geomatch

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// Compiler parses and compiles rules with settings: the geodata to read, the
// rule kinds and ext: files to allow, and limits, for example for rules that
// untrusted users write. The zero Compiler allows every rule, without limits,
// and reads no geodata, as the package's functions do. A Compiler may be
// used concurrently, and holds no state between calls.
//
// Rules that the settings do not allow are invalid: ParseRules rejects them
// as Compile does, so validating configuration catches them.
type Compiler struct {
	// GeoData reads geoip:, geosite: and ext: rules. Every Matcher compiled
	// with one GeoData shares the geodata entries compiled for it. Nil reads
	// no geodata: geoip:private uses the built-in ranges, ext: rules read
	// only absolute file names, and other geoip: and geosite: rules fail
	// with ErrNoGeoData.
	GeoData *GeoData
	// PlainDomain is the kind of a domain written without a kind, such as
	// example.com: RuleKeyword, the zero value, matches hosts containing
	// it, as rule lists usually mean it; RuleDomain matches it and its
	// subdomains; and RuleFull matches it exactly. With RuleDomain or
	// RuleFull, a leading dot, as in .example.com, means the subdomains
	// only. Rule.UnmarshalText and the package's functions read it as
	// RuleKeyword.
	PlainDomain RuleKind
	// Kinds are the rule kinds allowed; the zero KindSet allows all. Other
	// rules fail with a *KindError, which is an ErrKindDisabled.
	Kinds KindSet
	// ExtFiles is which files ext:, ext-ip: and ext-domain: rules may name.
	// The zero value, ExtAny, allows any; other rules fail with
	// ErrExtDenied. Relative names are looked up as GeoFiles.Dir tells.
	ExtFiles ExtAccess
	// Limits bound the rules of one call; rules beyond them fail with
	// ErrLimit.
	Limits Limits
}

// KindSet is a set of rule kinds. The zero KindSet stands for every kind.
type KindSet uint32

// Sets of rule kinds. RuleExt, whose kind depends on its file, is in
// neither IPKinds nor DomainKinds.
const (
	// AllKinds holds every kind.
	AllKinds KindSet = 1<<(RuleExt+1) - 1<<RuleIP
	// IPKinds holds the kinds that match IP addresses only, for rules about
	// addresses such as those of clients.
	IPKinds KindSet = 1<<RuleIP | 1<<RuleGeoIP
	// DomainKinds holds the kinds that match domain names only.
	DomainKinds KindSet = 1<<(RuleGeoSite+1) - 1<<RuleFull
	// GeoKinds holds the kinds that read geodata files: AllKinds &^ GeoKinds
	// leaves the rules that need no geodata.
	GeoKinds KindSet = 1<<RuleGeoIP | 1<<RuleGeoSite | 1<<RuleExt
)

// KindsOf returns the set of kinds. With none it returns the zero KindSet,
// which stands for every kind.
func KindsOf(kinds ...RuleKind) KindSet {
	var s KindSet
	for _, k := range kinds {
		s |= 1 << k
	}
	return s
}

// Without returns s without kinds, as in AllKinds.Without(RuleRegexp); the
// zero KindSet counts as AllKinds. Remove a set with &^, as in
// AllKinds &^ GeoKinds. A KindSet left empty is the zero KindSet, which
// holds every kind.
func (s KindSet) Without(kinds ...RuleKind) KindSet {
	base := s
	if base == 0 {
		base = AllKinds
	}
	return base &^ KindsOf(kinds...)
}

// String lists the kinds of s, as "ip, geoip"; the zero KindSet lists every
// kind.
func (s KindSet) String() string {
	var names []string
	for k := RuleIP; k <= RuleExt; k++ {
		if s.Has(k) {
			names = append(names, k.String())
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// Has reports whether s holds k; the zero KindSet holds every kind.
func (s KindSet) Has(k RuleKind) bool {
	if k < RuleIP || k > RuleExt {
		return false
	}
	return s == 0 || s&(1<<k) != 0
}

// ExtAccess is which files ext:, ext-ip: and ext-domain: rules may name.
type ExtAccess uint8

// Ext file access.
const (
	// ExtAny allows any file.
	ExtAny ExtAccess = iota
	// ExtLocal allows relative names that stay within the directory they
	// are looked up in, as GeoFiles.Dir tells: no absolute path, volume name
	// or .. element. Without such a directory it allows none.
	ExtLocal
	// ExtNone allows no ext: rules, so that only the files of GeoData are
	// read.
	ExtNone
)

// check reports whether an ext: rule may name file, looked up among the
// files v.
func (a ExtAccess) check(file string, v view) error {
	switch a {
	case ExtAny:
		return nil
	case ExtLocal:
		if !localFile(file) {
			return fmt.Errorf("%w: %s is not a local name", ErrExtDenied, file)
		}
		if v.extDir(path.Dir, kindAny) == "" {
			return fmt.Errorf("%w: no directory for ext: files; set GeoFiles.Dir", ErrExtDenied)
		}
		return nil
	case ExtNone:
		return fmt.Errorf("%w: ext: rules are disabled", ErrExtDenied)
	default:
		return fmt.Errorf("%w: unknown ExtAccess %d", ErrExtDenied, a)
	}
}

// Limits bound the rules of one ParseRules or Compile call. Zero fields do
// not limit.
type Limits struct {
	// MaxRules bounds the number of rules, not counting empty rules,
	// comments and rules skipped for other reasons.
	MaxRules int
	// MaxRuleLen bounds the length of a rule in bytes, without surrounding
	// spaces.
	MaxRuleLen int
	// MaxRegexps bounds the number of regexp: rules, which cost every
	// query some time.
	MaxRegexps int
}

// ParseRule parses one rule, in the syntax the package documentation lists,
// without reading any geodata. It fails for an empty rule or a comment.
func ParseRule(s string) (Rule, error) { return Compiler{}.ParseRule(s) }

// ParseRules parses rules as Compile reads them, without reading any
// geodata, for example to check configuration: empty rules and comments are
// skipped, and so are invalid rules, which the returned error lists as a
// RuleErrors. Rules that parse may still fail to compile if their geodata
// cannot be read.
func ParseRules(rules []string) ([]Rule, error) { return Compiler{}.ParseRules(rules) }

// Compile compiles rules into a Matcher without geodata; Compiler.Compile
// reads geodata. The package documentation lists the syntax.
//
// Empty rules and comments, starting with # or ;, are skipped. Invalid rules,
// and rules whose geodata cannot be read, are skipped too: the returned error
// is then a RuleErrors, and the Matcher holds the other rules. Since Index is
// the position in rules, Compile(SplitLines(text)) reports errors by line,
// Index+1 being the line number.
func Compile(rules []string) (*Matcher, error) { return Compiler{}.Compile(rules) }

// MustCompile is Compile that panics if a rule is skipped, for rules fixed
// in a program.
func MustCompile(rules []string) *Matcher {
	m, err := Compile(rules)
	if err != nil {
		panic(err)
	}
	return m
}

// CompileRules is Compile for parsed rules, such as those ParseRules
// returns or a program builds. Each rule is checked and normalized as its
// String form would be.
func CompileRules(rules []Rule) (*Matcher, error) { return Compiler{}.CompileRules(rules) }

// ParseRule is the package's ParseRule with the settings of c. Its error is
// a *RuleError, as ParseRules gives for each rule, with Index 0.
func (c Compiler) ParseRule(s string) (Rule, error) {
	r, err := c.reader(c.GeoData.view()).read(s)
	if err != nil {
		return Rule{}, &RuleError{Rule: trimRule(s), Err: err}
	}
	return r, nil
}

// ParseRules is the package's ParseRules with the settings of c.
func (c Compiler) ParseRules(rules []string) ([]Rule, error) {
	rd := c.reader(c.GeoData.view())
	var out []Rule
	var errs RuleErrors
	for i, s := range rules {
		r, err := rd.read(s)
		switch {
		case errors.Is(err, errNoRule):
		case err != nil:
			errs = append(errs, &RuleError{Index: i, Rule: trimRule(s), Err: err})
		default:
			out = append(out, r)
		}
	}
	return out, errs.err()
}

// Normalize returns rules as ParseRules reads them, in their canonical
// spelling and without duplicates, in order, for example to save
// configuration as it will be compiled. Empty rules and comments are
// dropped, and invalid rules, which the error lists as ParseRules does.
func (c Compiler) Normalize(rules []string) ([]string, error) {
	parsed, err := c.ParseRules(rules)
	out := make([]string, 0, len(parsed))
	seen := make(map[string]bool, len(parsed))
	for _, r := range parsed {
		if s := r.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, err
}

// Compile is the package's Compile with the settings of c.
func (c Compiler) Compile(rules []string) (*Matcher, error) {
	return c.compile(len(rules), func(i int) string { return rules[i] }, false)
}

// CompileRules is the package's CompileRules with the settings of c.
func (c Compiler) CompileRules(rules []Rule) (*Matcher, error) {
	return c.compile(len(rules), func(i int) string { return rules[i].String() }, true)
}

// compile compiles n rules, rule i written as text(i). Empty rules and
// comments are skipped as written text, but are errors for parsed rules,
// whose errors quote them as String writes them.
func (c Compiler) compile(n int, text func(int) string, parsed bool) (*Matcher, error) {
	b := newBuilder(c.GeoData)
	rd := c.reader(b.view)
	var errs RuleErrors
	for i := range n {
		s := text(i)
		r, err := rd.read(s)
		if !parsed {
			if errors.Is(err, errNoRule) {
				continue
			}
			s = trimRule(s)
		}
		if err == nil {
			err = b.add(r)
		}
		if err != nil {
			errs = append(errs, &RuleError{Index: i, Rule: s, Err: err})
		}
	}
	return b.finish(), errs.err()
}

// ruleReader parses the rules of one call, counting them for the limits.
type ruleReader struct {
	c              *Compiler
	view           view
	plain          RuleKind // the kind of plain domains
	plainErr       error    // of an invalid Compiler.PlainDomain
	rules, regexps int
}

func (c Compiler) reader(v view) *ruleReader {
	rd := &ruleReader{c: &c, view: v, plain: c.PlainDomain}
	switch rd.plain {
	case 0:
		rd.plain = RuleKeyword
	case RuleKeyword, RuleDomain, RuleFull:
	default:
		rd.plainErr = fmt.Errorf("%w: Compiler.PlainDomain is %v, not keyword, domain or full", ErrInvalidRule, rd.plain)
	}
	return rd
}

// read parses s and checks it against the settings. Its errors are
// ErrInvalidRule, or errNoRule for an empty rule or a comment.
func (rd *ruleReader) read(s string) (Rule, error) {
	if isComment(s) {
		return Rule{}, errNoRule
	}
	c, lim := rd.c, &rd.c.Limits
	if n := len(trimRule(s)); lim.MaxRuleLen > 0 && n > lim.MaxRuleLen {
		return Rule{}, fmt.Errorf("%w: %d bytes, more than %d", ErrLimit, n, lim.MaxRuleLen)
	}
	if rd.plainErr != nil {
		return Rule{}, rd.plainErr
	}
	r, err := parseRule(s, rd.plain)
	if err != nil {
		return Rule{}, withClass(err, ErrInvalidRule)
	}
	if !c.Kinds.Has(r.Kind) {
		return Rule{}, &KindError{Kind: r.Kind, Allowed: c.Kinds}
	}
	if r.File != "" {
		if err := c.ExtFiles.check(r.File, rd.view); err != nil {
			return Rule{}, err
		}
	}
	if lim.MaxRules > 0 && rd.rules >= lim.MaxRules {
		return Rule{}, fmt.Errorf("%w: more than %d rules", ErrLimit, lim.MaxRules)
	}
	if r.Kind == RuleRegexp {
		if lim.MaxRegexps > 0 && rd.regexps >= lim.MaxRegexps {
			return Rule{}, fmt.Errorf("%w: more than %d regexp: rules", ErrLimit, lim.MaxRegexps)
		}
		rd.regexps++
	}
	rd.rules++
	return r, nil
}

// localFile reports whether name stays within the directory it is looked up
// in on every operating system: relative, without .. elements, and without
// a volume name, taking backslashes for separators.
func localFile(name string) bool {
	slashed := strings.ReplaceAll(name, `\`, "/")
	return !strings.Contains(name, ":") && filepath.IsLocal(name) && filepath.IsLocal(slashed)
}
