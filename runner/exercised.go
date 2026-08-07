package main

import "sort"

// ExercisedCapabilities records the capability surface a run actually drove,
// as distinct from the profile's declared claims. It lets a published result
// state exactly which transports, categories, and capability tags were tested.
type ExercisedCapabilities struct {
	Transports     []string `json:"transports"`
	Categories     []string `json:"categories"`
	CapabilityTags []string `json:"capability_tags"`
}

// computeExercised derives the exercised surface from the applicable results by
// looking each case up by ID. A result whose case is absent is skipped rather
// than invented. Each dimension is returned sorted and de-duplicated.
func computeExercised(results []CaseResult, casesByID map[string]Case) ExercisedCapabilities {
	transports := map[string]struct{}{}
	categories := map[string]struct{}{}
	tags := map[string]struct{}{}
	for _, result := range results {
		c, ok := casesByID[result.CaseID]
		if !ok {
			continue
		}
		if c.Transport != "" {
			transports[c.Transport] = struct{}{}
		}
		if c.Category != "" {
			categories[c.Category] = struct{}{}
		}
		for _, tag := range c.CapabilityTags {
			if tag != "" {
				tags[tag] = struct{}{}
			}
		}
	}
	return ExercisedCapabilities{
		Transports:     sortedSetKeys(transports),
		Categories:     sortedSetKeys(categories),
		CapabilityTags: sortedSetKeys(tags),
	}
}

func sortedSetKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
