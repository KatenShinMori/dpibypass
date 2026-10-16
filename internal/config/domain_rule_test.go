package config

import (
	"testing"
)

func TestDomainNormalizationAndValidation(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"example.com.", true},
		{"*.example.com", true},
		{"*.sub.example.com", true},
		{"*.EXAMPLE.COM.", true},
		{"", false},
		{".", false},
		{"*. ", false},
		{"*", false},
		{"*.", false},
		{"*.*.example.com", false},
		{"example.*.com", false},
		{"example..com", false},
		{".example.com", false},
		{"*.example..com", false},
	}

	for _, tt := range tests {
		err := ValidateDomainPattern(tt.pattern)
		if tt.valid && err != nil {
			t.Errorf("ValidateDomainPattern(%q) unexpected error: %v", tt.pattern, err)
		} else if !tt.valid && err == nil {
			t.Errorf("ValidateDomainPattern(%q) expected error, got nil", tt.pattern)
		}
	}
}

func TestDomainMatcher(t *testing.T) {
	rules := []DomainRuleConfig{
		{Match: "example.com", Profile: "exact-example"},
		{Match: "sub.example.com.", Profile: "exact-sub-example"},
		{Match: "*.example.org", Profile: "wildcard-org"},
		{Match: "*.sub.example.org", Profile: "wildcard-sub-org"},
		{Match: "CASE.NET", Profile: "exact-case"},
	}

	matcher, err := NewDomainMatcher(rules)
	if err != nil {
		t.Fatalf("NewDomainMatcher failed: %v", err)
	}

	tests := []struct {
		query           string
		expectedProfile string
		expectedMatched bool
	}{
		// Exact match cases
		{"example.com", "exact-example", true},
		{"EXAMPLE.COM", "exact-example", true},
		{"example.com.", "exact-example", true},
		{"EXAMPLE.COM.", "exact-example", true},
		{"sub.example.com", "exact-sub-example", true},
		{"sub.example.com.", "exact-sub-example", true},
		{"case.net", "exact-case", true},
		{"CASE.NET.", "exact-case", true},

		// Wildcard cases
		{"foo.example.org", "wildcard-org", true},
		{"FOO.EXAMPLE.ORG.", "wildcard-org", true},
		{"deep.bar.example.org", "wildcard-org", true},

		// Specificity tie-breaking: *.sub.example.org must beat *.example.org
		{"alpha.sub.example.org", "wildcard-sub-org", true},
		{"deep.beta.sub.example.org", "wildcard-sub-org", true},

		// Wildcard strict boundary rejection:
		// *.example.org must NOT match example.org itself
		{"example.org", "", false},
		// *.example.org must NOT match notexample.org
		{"notexample.org", "", false},
		{"fakeexample.org", "", false},

		// Unmatched
		{"other.com", "", false},
		{"example.net", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		profile, matched := matcher.Match(tt.query)
		if matched != tt.expectedMatched {
			t.Errorf("Match(%q) matched=%v, expected=%v", tt.query, matched, tt.expectedMatched)
		}
		if profile != tt.expectedProfile {
			t.Errorf("Match(%q) profile=%q, expected=%q", tt.query, profile, tt.expectedProfile)
		}
	}
}

func TestDomainMatcherDuplicatesAndValidation(t *testing.T) {
	// 1. Duplicate exact rules (with case / trailing dot variation)
	dupRules1 := []DomainRuleConfig{
		{Match: "example.com", Profile: "p1"},
		{Match: "EXAMPLE.COM.", Profile: "p2"},
	}
	if _, err := NewDomainMatcher(dupRules1); err == nil {
		t.Error("expected error for duplicate exact domain rules, got nil")
	}

	// 2. Duplicate wildcard rules
	dupRules2 := []DomainRuleConfig{
		{Match: "*.example.com", Profile: "p1"},
		{Match: "*.EXAMPLE.COM.", Profile: "p2"},
	}
	if _, err := NewDomainMatcher(dupRules2); err == nil {
		t.Error("expected error for duplicate wildcard domain rules, got nil")
	}

	// 3. Empty profile
	emptyProfRules := []DomainRuleConfig{
		{Match: "example.com", Profile: ""},
	}
	if _, err := NewDomainMatcher(emptyProfRules); err == nil {
		t.Error("expected error for empty profile in domain rule, got nil")
	}

	// 4. Malformed pattern
	badPatternRules := []DomainRuleConfig{
		{Match: "*", Profile: "p1"},
	}
	if _, err := NewDomainMatcher(badPatternRules); err == nil {
		t.Error("expected error for malformed pattern, got nil")
	}
}

func TestDiscordUpdaterDomainMatching(t *testing.T) {
	cfg, err := Load("../../config.json")
	if err != nil {
		t.Fatalf("Load(../../config.json): %v", err)
	}

	matcher, err := NewDomainMatcher(cfg.DomainRules)
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}

	discordDomains := []string{
		"updates.discord.com",
		"stable.dl2.discordapp.net",
		"dl.discordapp.net",
		"dl2.discordapp.net",
		"cdn.discordapp.com",
		"router.discordapp.net",
		"gateway.discord.gg",
		"status.discord.com",
		"discordstatus.com",
		"latency.discord.media",
		"discord.com",
		"discordapp.com",
		"discordapp.net",
		"discord.gg",
		"discordcdn.com",
		"discord.gift",
		"dis.gd",
		"discord.dev",
		"discord.new",
		"discordapp.io",
		"discordactivities.com",
		"discord-activities.com",
	}

	for _, domain := range discordDomains {
		profile, matched := matcher.Match(domain)
		if !matched {
			t.Errorf("domain %q was not matched by domain rules in config.json", domain)
		}
		if profile != "packet-default" {
			t.Errorf("domain %q matched profile %q, expected 'packet-default'", domain, profile)
		}
	}

	// DoH endpoints must match "none" so they are never desynced
	dohDomains := []string{
		"cloudflare-dns.com",
		"dns.google",
		"one.one.one.one",
	}
	for _, domain := range dohDomains {
		profile, matched := matcher.Match(domain)
		if !matched {
			t.Errorf("DoH domain %q was not matched by domain rules in config.json", domain)
		}
		if profile != "none" {
			t.Errorf("DoH domain %q matched profile %q, expected 'none'", domain, profile)
		}
	}
}
