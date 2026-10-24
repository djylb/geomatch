package geomatch

import (
	"fmt"
	"slices"
)

type builder struct {
	geo      *GeoData
	view     view // the files of the GeoData, read once
	ips      ipSetBuilder
	geoIPs   []*ipSet
	inverse  []*ipSet
	domains  domainSet
	sites    []*domainSet
	ipRules  int
	domRules int
	probes   []probe
	sources  []source
}

func newBuilder(geo *GeoData) *builder {
	if geo == nil {
		geo = &GeoData{}
	}
	return &builder{geo: geo, view: geo.view()}
}

func (c *builder) finish() *Matcher {
	// Several geo entries become one set, so that a query looks once.
	if len(c.geoIPs) > 1 {
		c.geoIPs = []*ipSet{c.geo.mergedIPs(c.geoIPs)}
	}
	if len(c.sites) > 1 {
		c.sites = []*domainSet{c.geo.mergedSites(c.sites)}
	}
	m := &Matcher{
		ipSets:   c.geoIPs,
		inverse:  c.inverse,
		domSets:  c.sites,
		ipRules:  c.ipRules,
		domRules: c.domRules,
		probes:   c.probes,
		geo:      c.geo,
		cfgGen:   c.view.cfgGen,
		sources:  c.sources,
	}
	if own := c.ips.build(); own.ranges() > 0 {
		m.ipSets = append([]*ipSet{own}, m.ipSets...)
	}
	if c.domains.finish(); c.domains.active {
		m.domSets = append([]*domainSet{&c.domains}, m.domSets...)
	}
	return m
}

// add compiles a parsed rule.
func (c *builder) add(r Rule) error {
	p := probe{rule: r}
	switch r.Kind {
	case RuleIP:
		c.ips.addPrefix(r.Prefix)
		c.ipRules++
	case RuleGeoIP, RuleGeoSite, RuleExt:
		geo, site, src, err := c.geo.compiledRule(c.view, r)
		c.addSource(src)
		if err != nil {
			return withClass(err, ErrGeoData)
		}
		if geo != nil {
			c.addGeoIPSet(geo, r.Negate)
		} else {
			c.addSiteSet(site)
		}
		p.geo, p.site = geo, site
	case RuleFull:
		c.domains.addName(r.Value, nameExact)
		c.domRules++
	case RuleDomain:
		c.domains.addName(r.Value, nameExact|nameSub)
		c.domRules++
	case RuleSubdomain:
		c.domains.addName(r.Value, nameSub)
		c.domRules++
	case RuleKeyword:
		c.domains.addKeyword(r.Value)
		c.domRules++
	case RuleRegexp:
		if err := c.domains.addRegexp(r.Value); err != nil {
			return withClass(err, ErrInvalidRule)
		}
		c.domRules++
	case RuleDotless:
		if r.Value == "" {
			c.domains.dotlessAny = true
		} else {
			c.domains.dotless = append(c.domains.dotless, r.Value)
		}
		c.domRules++
	default:
		return withClass(fmt.Errorf("unknown rule kind %d", r.Kind), ErrInvalidRule)
	}
	c.probes = append(c.probes, p)
	return nil
}

// addSource records a geodata file that a rule read, or failed to.
func (c *builder) addSource(src *source) {
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
	c.ipRules++
}

func (c *builder) addSiteSet(site *domainSet) {
	if !slices.Contains(c.sites, site) {
		c.sites = append(c.sites, site)
	}
	c.domRules++
}
