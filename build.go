package geomatch

import (
	"errors"
	"fmt"
	"slices"
)

type builder struct {
	parent   *builder // of a builder of the rules of some ports: the one it serves
	geo      *GeoData // nil until a geo rule needs one, without a GeoData
	view     view     // the files of the GeoData, read once
	ips      ipSetBuilder
	geoIPs   []*ipSet
	inverse  []*ipSet
	domains  domainSet
	sites    []*domainSet
	ipRules  int
	domRules int
	probes   []probe
	sources  []source

	// The rules with ports: one builder for each set of ports, by its
	// text, in the order first used, and one of them all.
	groups    map[string]int
	groupList []portBuilder
	allPorted *builder
	portRules int
	anyAddr   bool // a port rule, in a builder of ports
}

type portBuilder struct {
	ports []PortRange
	b     *builder
}

func newBuilder(geo *GeoData) *builder {
	return &builder{geo: geo, view: geo.view()}
}

// geoData returns the GeoData of geo rules. Without one, the builder makes
// its own, without files, which indexes the files that ext: rules name by
// absolute paths, and with which the Matcher reports them Stale.
func (c *builder) geoData() *GeoData {
	if c.parent != nil {
		c.geo = c.parent.geoData()
		return c.geo
	}
	if c.geo == nil {
		c.geo = &GeoData{}
	}
	return c.geo
}

func (c *builder) finish() *Matcher {
	// Several geo entries become one set, so that a query looks once; they
	// come from geo rules, which set geo.
	if len(c.geoIPs) > 1 {
		c.geoIPs = []*ipSet{c.geo.mergedIPs(c.geoIPs)}
	}
	if len(c.sites) > 1 {
		c.sites = []*domainSet{c.geo.mergedSites(c.sites)}
	}
	m := &Matcher{
		ipSets:    c.geoIPs,
		inverse:   c.inverse,
		domSets:   c.sites,
		ipRules:   c.ipRules,
		domRules:  c.domRules,
		portRules: c.portRules,
		anyAddr:   c.anyAddr,
		probes:    c.probes,
		snapshot:  snapshot{geo: c.geo, cfgGen: c.view.cfgGen, sources: c.sources},
	}
	if own := c.ips.build(); own.ranges() > 0 {
		m.ipSets = append([]*ipSet{own}, m.ipSets...)
	}
	if c.domains.finish(); c.domains.active {
		m.domSets = append([]*domainSet{&c.domains}, m.domSets...)
	}
	if len(c.groupList) > 0 {
		groups := make([]portGroup, len(c.groupList))
		for i, g := range c.groupList {
			groups[i] = portGroup{ports: g.ports, m: g.b.finish()}
		}
		all := groups[0].m
		if len(groups) > 1 {
			all = c.allPorted.finish()
		}
		m.ports = newPortIndex(groups, all)
	}
	return m
}

// add compiles a parsed rule.
func (c *builder) add(r Rule) error {
	var p probe
	var err error
	if len(r.Ports) == 0 {
		p, err = c.compile(r)
	} else {
		p, err = c.addPorted(r)
	}
	if err != nil {
		return err
	}
	switch {
	case r.Kind == RulePort:
		c.ipRules++
		c.domRules++
	case r.Kind == RuleIP, r.Kind == RuleGeoIP, r.Kind == RuleExt && p.geo != nil:
		c.ipRules++
	default:
		c.domRules++
	}
	c.probes = append(c.probes, p)
	return nil
}

// addPorted compiles a rule with ports into the builder of its ports, and
// of all of them.
func (c *builder) addPorted(r Rule) (probe, error) {
	key := portsText(r.Ports)
	i, ok := c.groups[key]
	if !ok {
		if c.groups == nil {
			c.groups = make(map[string]int)
		}
		i = len(c.groupList)
		c.groups[key] = i
		c.groupList = append(c.groupList, portBuilder{ports: r.Ports, b: &builder{parent: c, geo: c.geo, view: c.view}})
		if c.allPorted == nil {
			c.allPorted = &builder{parent: c, geo: c.geo, view: c.view}
		}
	}
	base := r
	base.Ports = nil
	p, err := c.groupList[i].b.compile(base)
	if err != nil {
		if !ok {
			// No rule for the group: drop it.
			delete(c.groups, key)
			c.groupList = c.groupList[:i]
		}
		return probe{}, err
	}
	if _, err := c.allPorted.compile(base); err != nil {
		return probe{}, err // compiled once already, so not expected
	}
	c.portRules++
	p.rule, p.ports = r, slices.Clone(r.Ports)
	return p, nil
}

// compile compiles a rule into the sets of c and returns its probe.
func (c *builder) compile(r Rule) (probe, error) {
	p := probe{rule: r}
	switch r.Kind {
	case RuleIP:
		if r.Last.IsValid() {
			c.ips.addRange(r.Prefix.Addr(), r.Last)
		} else {
			c.ips.addPrefix(r.Prefix)
		}
	case RuleGeoIP, RuleGeoSite, RuleExt:
		geo, site, src, err := c.geoData().compiledRule(c.view, r)
		c.addSource(src)
		if err != nil {
			return probe{}, withClass(err, ErrGeoData)
		}
		if geo != nil {
			c.addGeoIPSet(geo, r.Negate)
		} else {
			c.addSiteSet(site)
		}
		p.geo, p.site = geo, site
	case RuleFull, RuleDomain, RuleSubdomain:
		c.domains.addName(r.Value, nameFlags(r.Kind))
	case RuleKeyword:
		c.domains.addKeyword(r.Value)
	case RuleRegexp:
		re, err := c.domains.addRegexp(r.Value)
		if err != nil {
			return probe{}, withClass(err, ErrInvalidRule)
		}
		p.re = re
	case RuleDotless:
		if r.Value == "" {
			c.domains.dotlessAny = true
		} else {
			c.domains.dotless = append(c.domains.dotless, r.Value)
		}
	case RulePort:
		if c.parent == nil {
			// Built only into the Matchers of ports, so that a Matcher's
			// own sets stay as they are.
			return probe{}, withClass(errors.New("a port rule without ports"), ErrInvalidRule)
		}
		c.anyAddr = true
	default:
		return probe{}, withClass(fmt.Errorf("unknown rule kind %d", r.Kind), ErrInvalidRule)
	}
	return p, nil
}

// addSource records a geodata file that a rule read, or failed to.
func (c *builder) addSource(src *source) {
	if c.parent != nil {
		c.parent.addSource(src)
		return
	}
	if src == nil || slices.ContainsFunc(c.sources, func(s source) bool { return s.name == src.name }) {
		return
	}
	c.sources = append(c.sources, *src)
}

func (c *builder) addGeoIPSet(geo *geoIPSet, negate bool) {
	list := &c.geoIPs
	if negate != geo.inverse {
		list = &c.inverse
	}
	if !slices.Contains(*list, geo.set) {
		*list = append(*list, geo.set)
	}
}

func (c *builder) addSiteSet(site *domainSet) {
	if !slices.Contains(c.sites, site) {
		c.sites = append(c.sites, site)
	}
}
