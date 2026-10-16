package config

import (
	"errors"
	"fmt"
	"strings"
)

// NormalizeDomain converts a hostname to lowercase and strips any trailing dot.
func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	return d
}

// ValidateDomainPattern checks that a match pattern is a valid exact domain
// or a valid wildcard pattern (e.g. *.example.com).
func ValidateDomainPattern(pattern string) error {
	p := NormalizeDomain(pattern)
	if p == "" {
		return errors.New("domain pattern cannot be empty")
	}

	if strings.HasPrefix(p, "*.") {
		suffix := p[2:]
		if suffix == "" {
			return errors.New("wildcard pattern must contain a domain suffix after '*.'")
		}
		if strings.Contains(suffix, "*") {
			return fmt.Errorf("wildcard pattern %q contains invalid additional '*' characters", pattern)
		}
		if strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") || strings.Contains(suffix, "..") {
			return fmt.Errorf("wildcard pattern %q has invalid label boundaries", pattern)
		}
		return nil
	}

	if strings.Contains(p, "*") {
		return fmt.Errorf("wildcard '*' is only permitted as a leading '*.' prefix, got %q", pattern)
	}

	if strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") || strings.Contains(p, "..") {
		return fmt.Errorf("domain %q has invalid label boundaries", pattern)
	}

	return nil
}

// CompiledDomainRule represents a validated, normalized domain matching rule.
type CompiledDomainRule struct {
	OriginalMatch string
	Normalized    string
	Profile       string
	IsWildcard    bool
	Suffix        string // for *.example.com, Suffix is "example.com"
}

// DomainMatcher evaluates hostnames against configured exact and wildcard domain rules.
// Matching precedence:
//  1. Exact match first.
//  2. Most-specific matching wildcard second (longest suffix).
//  3. Default profile if neither matches.
type DomainMatcher struct {
	exactRules    map[string]CompiledDomainRule
	wildcardRules []CompiledDomainRule
}

// NewDomainMatcher compiles and validates a slice of DomainRuleConfig.
// It rejects malformed patterns, duplicate normalized rules, and ambiguous definitions.
func NewDomainMatcher(rules []DomainRuleConfig) (*DomainMatcher, error) {
	matcher := &DomainMatcher{
		exactRules:    make(map[string]CompiledDomainRule),
		wildcardRules: make([]CompiledDomainRule, 0, len(rules)),
	}

	seenNormalized := make(map[string]string) // normalized pattern -> original pattern

	for i, r := range rules {
		if strings.TrimSpace(r.Profile) == "" {
			return nil, fmt.Errorf("domain rule %d (match %q) has empty profile", i, r.Match)
		}

		if err := ValidateDomainPattern(r.Match); err != nil {
			return nil, fmt.Errorf("domain rule %d has invalid match pattern %q: %w", i, r.Match, err)
		}

		norm := NormalizeDomain(r.Match)
		if orig, exists := seenNormalized[norm]; exists {
			return nil, fmt.Errorf("duplicate domain rule detected: %q normalizes to %q which conflicts with %q", r.Match, norm, orig)
		}
		seenNormalized[norm] = r.Match

		if strings.HasPrefix(norm, "*.") {
			rule := CompiledDomainRule{
				OriginalMatch: r.Match,
				Normalized:    norm,
				Profile:       r.Profile,
				IsWildcard:    true,
				Suffix:        norm[2:],
			}
			matcher.wildcardRules = append(matcher.wildcardRules, rule)
		} else {
			matcher.exactRules[norm] = CompiledDomainRule{
				OriginalMatch: r.Match,
				Normalized:    norm,
				Profile:       r.Profile,
				IsWildcard:    false,
			}
		}
	}

	return matcher, nil
}

// Match evaluates candidate domain against exact rules first, then wildcards by longest suffix.
// Wildcard rules such as *.example.org match subdomains only (e.g. sub.example.org, a.b.example.org).
// They DO NOT match example.org itself or notexample.org.
func (m *DomainMatcher) Match(domain string) (string, bool) {
	if m == nil {
		return "", false
	}

	norm := NormalizeDomain(domain)
	if norm == "" {
		return "", false
	}

	// 1. Exact match first
	if rule, ok := m.exactRules[norm]; ok {
		return rule.Profile, true
	}

	// 2. Wildcard matching: select the most-specific (longest suffix)
	var bestMatch *CompiledDomainRule
	for i := range m.wildcardRules {
		rule := &m.wildcardRules[i]
		// Wildcard requires strict subdomain boundary: domain must end with "." + rule.Suffix
		// and cannot be identical to rule.Suffix
		dotSuffix := "." + rule.Suffix
		if strings.HasSuffix(norm, dotSuffix) && len(norm) > len(dotSuffix) {
			if bestMatch == nil || len(rule.Suffix) > len(bestMatch.Suffix) {
				bestMatch = rule
			}
		}
	}

	if bestMatch != nil {
		return bestMatch.Profile, true
	}

	return "", false
}
