package geomatch

import (
	"errors"
	"fmt"
	"strings"
)

// Causes of a skipped rule, which errors.Is reports for a RuleError. Every
// cause is either ErrInvalidRule, a fault of the rule wherever it compiles,
// or ErrGeoData, a fault of the geodata at hand.
var (
	// ErrInvalidRule is the cause of a rule that cannot be compiled
	// anywhere: invalid syntax, or a rule that the Compiler does not allow.
	ErrInvalidRule = errors.New("geomatch: invalid rule")
	// ErrKindDisabled is the cause of a rule whose kind Compiler.Kinds
	// leaves out, which a *KindError details. It is an ErrInvalidRule.
	ErrKindDisabled = classed("rule kind not allowed", ErrInvalidRule)
	// ErrExtDenied is the cause of an ext: rule whose file Compiler.ExtFiles
	// does not allow. It is an ErrInvalidRule.
	ErrExtDenied = classed("geodata file not allowed", ErrInvalidRule)
	// ErrLimit is the cause of a rule beyond Compiler.Limits. It is an
	// ErrInvalidRule.
	ErrLimit = classed("rule limit exceeded", ErrInvalidRule)

	// ErrGeoData is the cause of a valid rule whose geodata cannot be read:
	// no file configured, a missing or malformed file, a missing code, or
	// an entry of the other kind. Other geodata may compile the rule.
	ErrGeoData = errors.New("geomatch: geodata unavailable")
	// ErrNoGeoData is returned when no geodata file is configured for a
	// geoip: or geosite: rule. It is an ErrGeoData.
	ErrNoGeoData = classed("no geodata file configured", ErrGeoData)
	// ErrCodeNotFound is returned when a geodata file has no entry for a
	// code. It is an ErrGeoData.
	ErrCodeNotFound = classed("code not found in geodata file", ErrGeoData)
)

// KindError is the cause of a rule whose kind Compiler.Kinds leaves out,
// with the kind read and the kinds allowed, for messages such as "only IP
// rules are allowed here". It is an ErrKindDisabled and an ErrInvalidRule.
type KindError struct {
	Kind    RuleKind
	Allowed KindSet
}

func (e *KindError) Error() string {
	return fmt.Sprintf("%v rules are not allowed here (allowed: %v)", e.Kind, e.Allowed)
}

func (e *KindError) Is(target error) bool {
	return target == ErrKindDisabled || target == ErrInvalidRule
}

// classErr is an error that errors.Is also reports as its class.
type classErr struct {
	msg   string
	class error
}

func classed(msg string, class error) error { return &classErr{msg, class} }

func (e *classErr) Error() string        { return e.msg }
func (e *classErr) Is(target error) bool { return target == e.class }

// causeErr marks err as a cause of class, keeping its message.
type causeErr struct {
	err   error
	class error
}

func (e *causeErr) Error() string        { return e.err.Error() }
func (e *causeErr) Unwrap() error        { return e.err }
func (e *causeErr) Is(target error) bool { return target == e.class }

// withClass returns err marked as a cause of class, unless it already is.
func withClass(err, class error) error {
	if err == nil || errors.Is(err, class) {
		return err
	}
	return &causeErr{err, class}
}

// RuleError reports a rule that was rejected or skipped, and why. errors.Is
// tells ErrInvalidRule from ErrGeoData.
type RuleError struct {
	// Index is the position of the rule in the slice given to ParseRules or
	// Compile.
	Index int
	Rule  string
	Err   error
}

// Error describes the rule and the cause, without Index, which RuleErrors
// adds for each rule of a list.
func (e *RuleError) Error() string {
	return fmt.Sprintf("geomatch: rule %q: %v", e.Rule, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// RuleErrors is the error of ParseRules, Compile and CompileRules: one
// *RuleError for each rule they skipped, in order. Get it with errors.As to
// go through the rules, or test for one cause with errors.Is.
type RuleErrors []*RuleError

func (e RuleErrors) Error() string {
	lines := make([]string, len(e))
	for i, re := range e {
		lines[i] = fmt.Sprintf("geomatch: rules[%d] %q: %v", re.Index, re.Rule, re.Err)
	}
	return strings.Join(lines, "\n")
}

// Unwrap returns the errors for errors.Is and errors.As.
func (e RuleErrors) Unwrap() []error {
	errs := make([]error, len(e))
	for i, re := range e {
		errs[i] = re
	}
	return errs
}

// Filter returns the errors whose cause is target, such as ErrInvalidRule
// to report configuration errors or ErrGeoData to report missing data.
func (e RuleErrors) Filter(target error) RuleErrors {
	var out RuleErrors
	for _, re := range e {
		if errors.Is(re, target) {
			out = append(out, re)
		}
	}
	return out
}

// err returns e as an error, or nil if it is empty.
func (e RuleErrors) err() error {
	if len(e) == 0 {
		return nil
	}
	return e
}
