package geomatch

import (
	"errors"
	"fmt"
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
	// their files relative to the working directory, and other geoip: and
	// geosite: rules fail with ErrNoGeoData.
	GeoData *GeoData
	// Kinds are the rule kinds allowed; the zero KindSet allows all. Other
	// rules fail with ErrKindDisabled.
	Kinds KindSet
	// ExtFiles is which files ext:, ext-ip: and ext-domain: rules may name.
	// The zero value, ExtAny, allows any; other rules fail with
	// ErrExtDenied.
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
	// are looked up in (GeoData.Dir, or the directory of the default file):
	// no absolute path, volume name or .. element.
	ExtLocal
	// ExtNone allows no ext: rules, so that only the files of GeoData are
	// read.
	ExtNone
)

// check reports whether an ext: rule may name file.
func (a ExtAccess) check(file string) error {
	switch a {
	case ExtAny:
		return nil
	case ExtLocal:
		if !localFile(file) {
			return fmt.Errorf("%w: %s is not a local name", ErrExtDenied, file)
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

// ParseRule is the package's ParseRule with the settings of c.
func (c Compiler) ParseRule(s string) (Rule, error) {
	r, err := c.reader().read(s)
	if err != nil {
		return Rule{}, fmt.Errorf("geomatch: rule %q: %w", trimRule(s), err)
	}
	return r, nil
}

// ParseRules is the package's ParseRules with the settings of c.
func (c Compiler) ParseRules(rules []string) ([]Rule, error) {
	rd := c.reader()
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

// Compile is the package's Compile with the settings of c.
func (c Compiler) Compile(rules []string) (*Matcher, error) {
	rd, b := c.reader(), newBuilder(c.GeoData)
	var errs RuleErrors
	for i, s := range rules {
		r, err := rd.read(s)
		if errors.Is(err, errNoRule) {
			continue
		}
		b.given++
		if err == nil {
			err = b.add(r)
		}
		if err != nil {
			errs = append(errs, &RuleError{Index: i, Rule: trimRule(s), Err: err})
		}
	}
	return b.finish(), errs.err()
}

// CompileRules is the package's CompileRules with the settings of c.
func (c Compiler) CompileRules(rules []Rule) (*Matcher, error) {
	rd, b := c.reader(), newBuilder(c.GeoData)
	var errs RuleErrors
	b.given = len(rules)
	for i, r := range rules {
		s := r.String()
		n, err := rd.read(s)
		if err == nil {
			err = b.add(n)
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
	rules, regexps int
}

func (c Compiler) reader() *ruleReader { return &ruleReader{c: &c} }

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
	r, err := parseRule(s)
	if err != nil {
		return Rule{}, withClass(err, ErrInvalidRule)
	}
	if !c.Kinds.Has(r.Kind) {
		return Rule{}, fmt.Errorf("%w: %s", ErrKindDisabled, r.Kind)
	}
	if r.File != "" {
		if err := c.ExtFiles.check(r.File); err != nil {
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
