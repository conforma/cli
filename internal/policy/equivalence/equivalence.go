// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package equivalence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
)

// ImageInfo represents information about an image for volatile config matching
type ImageInfo struct {
	Digest string
	Ref    string
	URL    string
}

// EquivalenceChecker determines whether two EnterpriseContractPolicy specs
// produce the same evaluation result for a given image at a specific time.
type EquivalenceChecker struct {
	effectiveTime time.Time
	imageInfo     *ImageInfo
}

// NewEquivalenceChecker creates a new equivalence checker with the given
// effective time and optional image information.
func NewEquivalenceChecker(effectiveTime time.Time, imageInfo *ImageInfo) *EquivalenceChecker {
	return &EquivalenceChecker{
		effectiveTime: effectiveTime,
		imageInfo:     imageInfo,
	}
}

// PolicyBucket represents a group of sources with identical policy and data sets
type PolicyBucket struct {
	PolicyURIs []string
	DataURIs   []string
	RuleData   map[string]interface{}
	Include    []string
	Exclude    []string
}

// NormalizedPolicy represents a policy spec after normalization
type NormalizedPolicy struct {
	Buckets []PolicyBucket
}

// AreEquivalent determines if two EnterpriseContractPolicy specs are equivalent
// for the given effective time and image.
func (ec *EquivalenceChecker) AreEquivalent(spec1, spec2 ecc.EnterpriseContractPolicySpec) (bool, error) {
	norm1, err := ec.normalizePolicy(spec1)
	if err != nil {
		return false, fmt.Errorf("failed to normalize first policy: %w", err)
	}

	norm2, err := ec.normalizePolicy(spec2)
	if err != nil {
		return false, fmt.Errorf("failed to normalize second policy: %w", err)
	}

	return ec.compareNormalizedPolicies(norm1, norm2)
}

// normalizePolicy converts an EnterpriseContractPolicySpec into a normalized form
// for comparison.
func (ec *EquivalenceChecker) normalizePolicy(spec ecc.EnterpriseContractPolicySpec) (*NormalizedPolicy, error) {
	// Step 1: Merge global configuration into each source
	sources := ec.mergeGlobalConfig(spec)

	// Step 2: Build buckets keyed by (policy set, data set)
	buckets := ec.buildBuckets(sources)

	// Step 3: Normalize each bucket
	normalizedBuckets := make([]PolicyBucket, 0, len(buckets))
	for _, bucket := range buckets {
		normalized, err := ec.normalizeBucket(bucket)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize bucket: %w", err)
		}
		normalizedBuckets = append(normalizedBuckets, normalized)
	}

	return &NormalizedPolicy{Buckets: normalizedBuckets}, nil
}

// mergeGlobalConfig merges deprecated Spec.Configuration into each source
func (ec *EquivalenceChecker) mergeGlobalConfig(spec ecc.EnterpriseContractPolicySpec) []ecc.Source {
	sources := make([]ecc.Source, len(spec.Sources))
	copy(sources, spec.Sources)

	// If there's global configuration, merge it into each source
	if spec.Configuration != nil {
		for i := range sources {
			if sources[i].Config == nil {
				sources[i].Config = &ecc.SourceConfig{}
			}

			// Merge include lists
			if len(spec.Configuration.Include) > 0 {
				sources[i].Config.Include = append(sources[i].Config.Include, spec.Configuration.Include...)
			}

			// Merge exclude lists
			if len(spec.Configuration.Exclude) > 0 {
				sources[i].Config.Exclude = append(sources[i].Config.Exclude, spec.Configuration.Exclude...)
			}
		}
	}

	return sources
}

// buildBuckets groups sources by their policy and data URI sets
func (ec *EquivalenceChecker) buildBuckets(sources []ecc.Source) map[string][]ecc.Source {
	buckets := make(map[string][]ecc.Source)

	for _, source := range sources {
		// Create bucket key from policy and data URIs
		policySet := ec.normalizeURISet(source.Policy)
		dataSet := ec.normalizeURISet(source.Data)
		key := fmt.Sprintf("%s|%s", policySet, dataSet)

		buckets[key] = append(buckets[key], source)
	}

	return buckets
}

// normalizeURISet converts a slice of URIs into a normalized string representation
func (ec *EquivalenceChecker) normalizeURISet(uris []string) string {
	// Create a set (deduplicate) and sort
	set := make(map[string]bool)
	for _, uri := range uris {
		// Normalize URI by stripping digest and protocol for comparison
		normalizedURI := ec.normalizeURI(uri)
		set[normalizedURI] = true
	}

	var sorted []string
	for uri := range set {
		sorted = append(sorted, uri)
	}
	sort.Strings(sorted)

	return strings.Join(sorted, ",")
}

var (
	protoPrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*::`)
	ociDigest   = regexp.MustCompile(`@[A-Za-z0-9]+:[A-Za-z0-9]+$`)
	queryOrFrag = regexp.MustCompile(`[?#].*$`)
)

// normalizeURI removes digest and protocols from URI for comparison purposes
func (ec *EquivalenceChecker) normalizeURI(uri string) string {
	s := strings.TrimSpace(uri)
	s = protoPrefix.ReplaceAllString(s, "") // strip leading "oci::", "git::", etc.
	s = queryOrFrag.ReplaceAllString(s, "") // drop ?ref=... and #...
	s = ociDigest.ReplaceAllString(s, "")   // strip trailing @sha256:...
	return s
}

// normalizeBucket normalizes a bucket of sources with identical policy/data sets
func (ec *EquivalenceChecker) normalizeBucket(sources []ecc.Source) (PolicyBucket, error) {
	if len(sources) == 0 {
		return PolicyBucket{}, fmt.Errorf("empty bucket")
	}

	// All sources in a bucket have the same policy and data URIs
	policyURIs := ec.normalizeURISet(sources[0].Policy)
	dataURIs := ec.normalizeURISet(sources[0].Data)

	// Merge RuleData from all sources in the bucket
	ruleData, err := ec.mergeRuleData(sources)
	if err != nil {
		return PolicyBucket{}, fmt.Errorf("failed to merge rule data: %w", err)
	}

	// Merge include/exclude matchers from all sources
	include, exclude := ec.mergeMatchers(sources)

	return PolicyBucket{
		PolicyURIs: strings.Split(policyURIs, ","),
		DataURIs:   strings.Split(dataURIs, ","),
		RuleData:   ruleData,
		Include:    include,
		Exclude:    exclude,
	}, nil
}

// mergeRuleData merges RuleData from multiple sources in deterministic order
func (ec *EquivalenceChecker) mergeRuleData(sources []ecc.Source) (map[string]interface{}, error) {
	type item struct {
		key string
		m   map[string]interface{}
	}
	var items []item

	// Process sources and create deterministic ordering
	for _, source := range sources {
		if source.RuleData == nil {
			continue
		}

		// Convert RuleData JSON to map[string]interface{}
		var ruleData map[string]interface{}
		if err := json.Unmarshal(source.RuleData.Raw, &ruleData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule data: %w", err)
		}

		// Create deterministic key based on canonical JSON hash
		canonicalBytes, err := marshalCanonical(ruleData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal canonical rule data: %w", err)
		}
		key := fmt.Sprintf("%x", sha256.Sum256(canonicalBytes))

		items = append(items, item{key: key, m: ruleData})
	}

	// Sort by deterministic key to ensure stable merge order
	sort.Slice(items, func(i, j int) bool {
		return items[i].key < items[j].key
	})

	// Merge in deterministic order
	merged := make(map[string]interface{})
	for _, item := range items {
		if err := ec.mergeJSON(merged, item.m); err != nil {
			return nil, fmt.Errorf("failed to merge rule data: %w", err)
		}
	}

	return merged, nil
}

// canonicalizeJSON converts a JSON value to canonical form (sorted keys)
func (ec *EquivalenceChecker) canonicalizeJSON(data interface{}) (map[string]interface{}, error) {
	// Use deterministic JSON encoding and then unmarshal to get canonical structure
	jsonBytes, err := marshalCanonical(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical JSON: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal canonical JSON: %w", err)
	}

	return result, nil
}

// mergeJSON merges two JSON objects, with the second taking precedence
func (ec *EquivalenceChecker) mergeJSON(target, source map[string]interface{}) error {
	for key, value := range source {
		if existing, exists := target[key]; exists {
			// If both values are objects, merge recursively
			if targetObj, ok := existing.(map[string]interface{}); ok {
				if sourceObj, ok := value.(map[string]interface{}); ok {
					if err := ec.mergeJSON(targetObj, sourceObj); err != nil {
						return err
					}
					continue
				}
			}
		}
		// Otherwise, source value takes precedence
		target[key] = value
	}
	return nil
}

// mergeMatchers merges include/exclude matchers from all sources in a bucket
func (ec *EquivalenceChecker) mergeMatchers(sources []ecc.Source) ([]string, []string) {
	var allInclude []string
	var allExclude []string

	for _, source := range sources {
		// Add static config matchers
		if source.Config != nil {
			allInclude = append(allInclude, source.Config.Include...)
			allExclude = append(allExclude, source.Config.Exclude...)
		}

		// Add active volatile config matchers
		if source.VolatileConfig != nil {
			activeInclude, activeExclude := ec.getActiveVolatileMatchers(source.VolatileConfig)
			allInclude = append(allInclude, activeInclude...)
			allExclude = append(allExclude, activeExclude...)
		}
	}

	// Normalize and deduplicate
	normalizedInclude := ec.normalizeMatchers(allInclude)
	normalizedExclude := ec.normalizeMatchers(allExclude)

	return normalizedInclude, normalizedExclude
}

// getActiveVolatileMatchers returns include/exclude matchers that are currently active
func (ec *EquivalenceChecker) getActiveVolatileMatchers(volatileConfig *ecc.VolatileSourceConfig) ([]string, []string) {
	var activeInclude []string
	var activeExclude []string

	// Check include matchers
	for _, matcher := range volatileConfig.Include {
		if ec.isVolatileMatcherActive(matcher) {
			activeInclude = append(activeInclude, matcher.Value)
		}
	}

	// Check exclude matchers
	for _, matcher := range volatileConfig.Exclude {
		if ec.isVolatileMatcherActive(matcher) {
			activeExclude = append(activeExclude, matcher.Value)
		}
	}

	return activeInclude, activeExclude
}

// isVolatileMatcherActive determines if a volatile matcher is currently active
func (ec *EquivalenceChecker) isVolatileMatcherActive(matcher ecc.VolatileCriteria) bool {
	// Check effective time constraints
	if matcher.EffectiveOn != "" {
		if effectiveOn, err := time.Parse(time.RFC3339, matcher.EffectiveOn); err == nil {
			if ec.effectiveTime.Before(effectiveOn) {
				return false
			}
		}
	}
	if matcher.EffectiveUntil != "" {
		if effectiveUntil, err := time.Parse(time.RFC3339, matcher.EffectiveUntil); err == nil {
			if ec.effectiveTime.After(effectiveUntil) {
				return false
			}
		}
	}

	// Check image matching constraints (if image info is provided)
	if ec.imageInfo != nil {
		if matcher.ImageDigest != "" && matcher.ImageDigest != ec.imageInfo.Digest {
			return false
		}
		if matcher.ImageRef != "" && matcher.ImageRef != ec.imageInfo.Ref {
			return false
		}
		if matcher.ImageUrl != "" && matcher.ImageUrl != ec.imageInfo.URL {
			return false
		}
	}

	return true
}

// normalizeMatchers normalizes a list of matchers
func (ec *EquivalenceChecker) normalizeMatchers(matchers []string) []string {
	// Create a set to deduplicate
	set := make(map[string]bool)
	for _, matcher := range matchers {
		normalized := ec.normalizeMatcher(matcher)
		set[normalized] = true
	}

	// Convert back to sorted slice
	var result []string
	for matcher := range set {
		result = append(result, matcher)
	}
	sort.Strings(result)

	return result
}

// normalizeMatcher normalizes a single matcher
func (ec *EquivalenceChecker) normalizeMatcher(matcher string) string {
	// Handle pkg.* -> pkg normalization
	if strings.HasSuffix(matcher, ".*") {
		return strings.TrimSuffix(matcher, ".*")
	}
	return matcher
}

// compareNormalizedPolicies compares two normalized policies for equivalence
func (ec *EquivalenceChecker) compareNormalizedPolicies(norm1, norm2 *NormalizedPolicy) (bool, error) {
	// Must have the same number of buckets
	if len(norm1.Buckets) != len(norm2.Buckets) {
		return false, nil
	}

	// Create a map of buckets from the second policy for efficient lookup
	bucketMap := make(map[string]PolicyBucket)
	for _, bucket := range norm2.Buckets {
		key := ec.bucketKey(bucket)
		bucketMap[key] = bucket
	}

	// Check that each bucket in the first policy has an equivalent bucket in the second
	for _, bucket1 := range norm1.Buckets {
		key := ec.bucketKey(bucket1)
		bucket2, exists := bucketMap[key]
		if !exists {
			return false, nil
		}

		bucketsEqual, err := ec.bucketsEqual(bucket1, bucket2)
		if err != nil {
			return false, fmt.Errorf("failed to compare buckets: %w", err)
		}
		if !bucketsEqual {
			return false, nil
		}
	}

	return true, nil
}

// bucketKey creates a unique key for a bucket based on policy and data URIs
func (ec *EquivalenceChecker) bucketKey(bucket PolicyBucket) string {
	policyKey := strings.Join(bucket.PolicyURIs, ",")
	dataKey := strings.Join(bucket.DataURIs, ",")
	return fmt.Sprintf("%s|%s", policyKey, dataKey)
}

// bucketsEqual compares two buckets for equivalence
func (ec *EquivalenceChecker) bucketsEqual(bucket1, bucket2 PolicyBucket) (bool, error) {
	// Compare policy URIs
	if !ec.stringSlicesEqual(bucket1.PolicyURIs, bucket2.PolicyURIs) {
		return false, nil
	}

	// Compare data URIs
	if !ec.stringSlicesEqual(bucket1.DataURIs, bucket2.DataURIs) {
		return false, nil
	}

	// Compare RuleData by canonicalizing and hashing
	ruleDataEqual, err := ec.ruleDataEqual(bucket1.RuleData, bucket2.RuleData)
	if err != nil {
		return false, fmt.Errorf("failed to compare rule data: %w", err)
	}
	if !ruleDataEqual {
		return false, nil
	}

	// Compare include matchers
	if !ec.stringSlicesEqual(bucket1.Include, bucket2.Include) {
		return false, nil
	}

	// Compare exclude matchers
	if !ec.stringSlicesEqual(bucket1.Exclude, bucket2.Exclude) {
		return false, nil
	}

	return true, nil
}

// stringSlicesEqual compares two string slices for equality
func (ec *EquivalenceChecker) stringSlicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i, s1 := range slice1 {
		if s1 != slice2[i] {
			return false
		}
	}

	return true
}

// ruleDataEqual compares two RuleData objects for equality by canonicalizing and hashing
func (ec *EquivalenceChecker) ruleDataEqual(data1, data2 map[string]interface{}) (bool, error) {
	hash1, err := ec.hashRuleData(data1)
	if err != nil {
		return false, fmt.Errorf("failed to hash first rule data: %w", err)
	}

	hash2, err := ec.hashRuleData(data2)
	if err != nil {
		return false, fmt.Errorf("failed to hash second rule data: %w", err)
	}

	return hash1 == hash2, nil
}

// hashRuleData creates a hash of canonicalized RuleData
func (ec *EquivalenceChecker) hashRuleData(data map[string]interface{}) (string, error) {
	// Use deterministic JSON encoding with sorted keys
	jsonBytes, err := marshalCanonical(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal canonical JSON: %w", err)
	}

	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%x", hash), nil
}
