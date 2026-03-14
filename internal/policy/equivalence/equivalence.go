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
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/pmezard/go-difflib/difflib"
)

// ImageInfo represents information about an image for volatile config matching
type ImageInfo struct {
	Digest string
	Ref    string
	URL    string
}

// DiffKind represents the type of difference
type DiffKind string

const (
	DiffAdded   DiffKind = "added"
	DiffRemoved DiffKind = "removed"
	DiffChanged DiffKind = "changed"
)

// FieldPath represents a structured path to a field (e.g. ["ruleData","paths","/foo/bar"])
type FieldPath []string

// PolicyDifference represents a structured difference between two policies
type PolicyDifference struct {
	BucketKey     string
	Field         string    // kept for compatibility and sorting
	Path          FieldPath // future-proof path support
	Kind          DiffKind
	VSAValue      any
	SuppliedValue any
	Summary       string
}

func (pd PolicyDifference) IsAdded() bool   { return pd.Kind == DiffAdded }
func (pd PolicyDifference) IsRemoved() bool { return pd.Kind == DiffRemoved }
func (pd PolicyDifference) IsChanged() bool { return pd.Kind == DiffChanged }

// EquivalenceChecker determines whether two EnterpriseContractPolicy specs
// produce the same evaluation result for a given image at a specific time.
type EquivalenceChecker struct {
	effectiveTime time.Time
	imageInfo     *ImageInfo
}

func NewEquivalenceChecker(effectiveTime time.Time, imageInfo *ImageInfo) *EquivalenceChecker {
	return &EquivalenceChecker{effectiveTime: effectiveTime, imageInfo: imageInfo}
}

// PolicyBucket represents one normalized policy "source entry"
type PolicyBucket struct {
	PolicyURIs []string
	DataURIs   []string
	RuleData   map[string]interface{}
	Include    []string
	Exclude    []string
	// Optional labels (collected names from sources) for nicer headers (if desired later)
	Names []string
}

// NormalizedPolicy is a normalized view of a policy spec
type NormalizedPolicy struct {
	Buckets []PolicyBucket
}

// AreEquivalent checks equivalence only
func (ec *EquivalenceChecker) AreEquivalent(spec1, spec2 ecc.EnterpriseContractPolicySpec) (bool, error) {
	eq, _, err := ec.AreEquivalentWithDifferences(spec1, spec2)
	return eq, err
}

// NormalizePolicy exposes normalization publicly
func (ec *EquivalenceChecker) NormalizePolicy(spec ecc.EnterpriseContractPolicySpec) (*NormalizedPolicy, error) {
	return ec.normalizePolicy(spec)
}

// AreEquivalentWithDifferences returns equivalence and structured diffs
func (ec *EquivalenceChecker) AreEquivalentWithDifferences(spec1, spec2 ecc.EnterpriseContractPolicySpec) (bool, []PolicyDifference, error) {
	norm1, err := ec.normalizePolicy(spec1)
	if err != nil {
		return false, nil, fmt.Errorf("failed to normalize first policy: %w", err)
	}
	norm2, err := ec.normalizePolicy(spec2)
	if err != nil {
		return false, nil, fmt.Errorf("failed to normalize second policy: %w", err)
	}
	eq, diffs := ec.compareNormalizedPoliciesWithDifferences(norm1, norm2)
	return eq, diffs, nil
}

// ---------- Normalization ----------

func (ec *EquivalenceChecker) normalizePolicy(spec ecc.EnterpriseContractPolicySpec) (*NormalizedPolicy, error) {
	sources := ec.mergeGlobalConfig(spec)
	buckets := ec.buildBuckets(sources)

	out := make([]PolicyBucket, 0, len(buckets))
	for _, group := range buckets {
		nb, err := ec.normalizeBucket(group)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize: %w", err)
		}
		out = append(out, nb)
	}
	return &NormalizedPolicy{Buckets: out}, nil
}

// merge deprecated spec.Configuration into each source entry
func (ec *EquivalenceChecker) mergeGlobalConfig(spec ecc.EnterpriseContractPolicySpec) []ecc.Source {
	sources := make([]ecc.Source, len(spec.Sources))
	copy(sources, spec.Sources)

	if spec.Configuration != nil {
		for i := range sources {
			if sources[i].Config == nil {
				sources[i].Config = &ecc.SourceConfig{}
			}
			if len(spec.Configuration.Include) > 0 {
				sources[i].Config.Include = append(sources[i].Config.Include, spec.Configuration.Include...)
			}
			if len(spec.Configuration.Exclude) > 0 {
				sources[i].Config.Exclude = append(sources[i].Config.Exclude, spec.Configuration.Exclude...)
			}
		}
	}
	return sources
}

// group sources by normalized (policy set, data set)
func (ec *EquivalenceChecker) buildBuckets(sources []ecc.Source) map[string][]ecc.Source {
	b := make(map[string][]ecc.Source)
	for _, s := range sources {
		policySet := ec.normalizeURISet(s.Policy)
		dataSet := ec.normalizeURISet(s.Data)
		key := policySet + "|" + dataSet
		b[key] = append(b[key], s)
	}
	return b
}

func (ec *EquivalenceChecker) normalizeURISet(uris []string) string {
	set := map[string]struct{}{}
	for _, u := range uris {
		set[ec.normalizeURI(u)] = struct{}{}
	}
	var arr []string
	for u := range set {
		arr = append(arr, u)
	}
	sort.Strings(arr)
	return strings.Join(arr, ",")
}

var (
	protoPrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*::`)  // oci:: git:: file:: etc
	ociDigest   = regexp.MustCompile(`@[A-Za-z0-9]+:[A-Za-z0-9]+$`) // @sha256:...
	queryOrFrag = regexp.MustCompile(`[?#].*$`)                     // drop ?ref=... / #...
)

// strip protocol, query/fragment, and digest
func (ec *EquivalenceChecker) normalizeURI(uri string) string {
	s := strings.TrimSpace(uri)
	// strip http(s):// if present
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	// strip proto::
	s = protoPrefix.ReplaceAllString(s, "")
	// drop ?... or #...
	s = queryOrFrag.ReplaceAllString(s, "")
	// drop trailing @algo:hash
	s = ociDigest.ReplaceAllString(s, "")
	return s
}

func (ec *EquivalenceChecker) normalizeBucket(sources []ecc.Source) (PolicyBucket, error) {
	if len(sources) == 0 {
		return PolicyBucket{}, fmt.Errorf("empty source group")
	}
	policy := strings.Split(ec.normalizeURISet(sources[0].Policy), ",")
	data := strings.Split(ec.normalizeURISet(sources[0].Data), ",")

	ruleData, err := ec.mergeRuleData(sources)
	if err != nil {
		return PolicyBucket{}, err
	}
	include, exclude := ec.mergeMatchers(sources)

	// collect names (if present on ecc.Source)
	nameSet := map[string]struct{}{}
	for _, s := range sources {
		if s.Name != "" {
			nameSet[s.Name] = struct{}{}
		}
	}
	var names []string
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)

	return PolicyBucket{
		PolicyURIs: policy,
		DataURIs:   data,
		RuleData:   ruleData,
		Include:    include,
		Exclude:    exclude,
		Names:      names,
	}, nil
}

func (ec *EquivalenceChecker) mergeRuleData(sources []ecc.Source) (map[string]interface{}, error) {
	type item struct {
		key string
		m   map[string]interface{}
	}
	var items []item

	for _, s := range sources {
		if s.RuleData == nil {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(s.RuleData.Raw, &m); err != nil {
			return nil, fmt.Errorf("unmarshal ruleData: %w", err)
		}
		cb, err := marshalCanonical(m)
		if err != nil {
			return nil, fmt.Errorf("canonicalize ruleData: %w", err)
		}
		items = append(items, item{
			key: fmt.Sprintf("%x", sha256.Sum256(cb)),
			m:   m,
		})
	}

	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })

	merged := map[string]interface{}{}
	for _, it := range items {
		if err := ec.mergeJSON(merged, it.m); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

func (ec *EquivalenceChecker) mergeJSON(dst, src map[string]interface{}) error {
	for k, v := range src {
		if ex, ok := dst[k]; ok {
			dm, ok1 := ex.(map[string]interface{})
			sm, ok2 := v.(map[string]interface{})
			if ok1 && ok2 {
				if err := ec.mergeJSON(dm, sm); err != nil {
					return err
				}
				continue
			}
		}
		dst[k] = v
	}
	return nil
}

func (ec *EquivalenceChecker) mergeMatchers(sources []ecc.Source) ([]string, []string) {
	var inc, exc []string
	for _, s := range sources {
		if s.Config != nil {
			inc = append(inc, s.Config.Include...)
			exc = append(exc, s.Config.Exclude...)
		}
		if s.VolatileConfig != nil {
			ai, ae := ec.getActiveVolatileMatchers(s.VolatileConfig)
			inc, exc = append(inc, ai...), append(exc, ae...)
		}
	}
	return ec.normalizeMatchers(inc), ec.normalizeMatchers(exc)
}

func (ec *EquivalenceChecker) getActiveVolatileMatchers(v *ecc.VolatileSourceConfig) ([]string, []string) {
	var inc, exc []string
	for _, m := range v.Include {
		if ec.isVolatileMatcherActive(m) {
			inc = append(inc, m.Value)
		}
	}
	for _, m := range v.Exclude {
		if ec.isVolatileMatcherActive(m) {
			exc = append(exc, m.Value)
		}
	}
	return inc, exc
}

func (ec *EquivalenceChecker) isVolatileMatcherActive(m ecc.VolatileCriteria) bool {
	if m.EffectiveOn != "" {
		if t, err := time.Parse(time.RFC3339, m.EffectiveOn); err == nil && ec.effectiveTime.Before(t) {
			return false
		}
	}
	if m.EffectiveUntil != "" {
		if t, err := time.Parse(time.RFC3339, m.EffectiveUntil); err == nil && ec.effectiveTime.After(t) {
			return false
		}
	}
	if ec.imageInfo != nil {
		if m.ImageDigest != "" && m.ImageDigest != ec.imageInfo.Digest {
			return false
		}
		if m.ImageRef != "" && m.ImageRef != ec.imageInfo.Ref {
			return false
		}
		if m.ImageUrl != "" && m.ImageUrl != ec.imageInfo.URL {
			return false
		}
	}
	return true
}

func (ec *EquivalenceChecker) normalizeMatchers(ms []string) []string {
	set := map[string]struct{}{}
	for _, m := range ms {
		m = strings.TrimSpace(m)
		m = strings.TrimSuffix(m, ".*") // pkg.* -> pkg
		if m != "" {
			set[m] = struct{}{}
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------- Comparison + pairing + Git-style diff ----------

func (ec *EquivalenceChecker) compareNormalizedPoliciesWithDifferences(norm1, norm2 *NormalizedPolicy) (bool, []PolicyDifference) {
	var diffs []PolicyDifference

	// Index by exact key first
	m1 := map[string]PolicyBucket{}
	for _, b := range norm1.Buckets {
		m1[ec.bucketKey(b)] = b
	}
	m2 := map[string]PolicyBucket{}
	for _, b := range norm2.Buckets {
		m2[ec.bucketKey(b)] = b
	}

	// Exact matches → field-level diffs
	used1 := map[string]bool{}
	used2 := map[string]bool{}
	for k, b1 := range m1 {
		if b2, ok := m2[k]; ok {
			used1[k], used2[k] = true, true
			diffs = append(diffs, ec.compareBucketsWithDifferences(b1, b2)...)
		}
	}

	// Collect unmatched (candidates for pairing)
	var removed, added []PolicyBucket
	for k, b := range m1 {
		if !used1[k] {
			removed = append(removed, b)
		}
	}
	for k, b := range m2 {
		if !used2[k] {
			added = append(added, b)
		}
	}

	// Pair near-identical entries so we show CHANGES, not ADD/REMOVE
	pairsR2A, unmatchedRemoved, unmatchedAdded := ec.pairBuckets(removed, added)

	// Produce field-level diffs for paired entries
	for _, p := range pairsR2A {
		diffs = append(diffs, ec.compareBucketsWithDifferences(p.r, p.a)...)
	}

	// Remaining unmatched → added/removed source entries
	for _, b := range unmatchedRemoved {
		diffs = append(diffs, PolicyDifference{
			BucketKey: ec.bucketKey(b),
			Field:     "sources",
			Path:      FieldPath{"sources"},
			Kind:      DiffRemoved,
			VSAValue:  ec.describeSource(b),
			Summary:   "source entry removed",
		})
	}
	for _, b := range unmatchedAdded {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     ec.bucketKey(b),
			Field:         "sources",
			Path:          FieldPath{"sources"},
			Kind:          DiffAdded,
			SuppliedValue: ec.describeSource(b),
			Summary:       "source entry added",
		})
	}

	return len(diffs) == 0, diffs
}

// Pairing: greedy best-match by similarity to avoid noisy add/remove
type bucketPair struct{ r, a PolicyBucket }

func (ec *EquivalenceChecker) pairBuckets(removed, added []PolicyBucket) (pairs []bucketPair, remOut []PolicyBucket, addOut []PolicyBucket) {
	if len(removed) == 0 || len(added) == 0 {
		return nil, removed, added
	}

	// Build all candidate scores
	type cand struct {
		i, j  int
		score float64
	}
	var all []cand
	for i := range removed {
		for j := range added {
			s := ec.bucketSimilarity(removed[i], added[j])
			if s > 0 {
				all = append(all, cand{i: i, j: j, score: s})
			}
		}
	}
	// Sort by descending score
	sort.Slice(all, func(i, j int) bool { return all[i].score > all[j].score })

	usedR := make([]bool, len(removed))
	usedA := make([]bool, len(added))
	const threshold = 0.60 // tweakable; >=0.60 is "same entry, changed"
	for _, c := range all {
		if usedR[c.i] || usedA[c.j] {
			continue
		}
		if c.score >= threshold {
			usedR[c.i] = true
			usedA[c.j] = true
			pairs = append(pairs, bucketPair{r: removed[c.i], a: added[c.j]})
		}
	}
	for i, b := range removed {
		if !usedR[i] {
			remOut = append(remOut, b)
		}
	}
	for j, b := range added {
		if !usedA[j] {
			addOut = append(addOut, b)
		}
	}
	return
}

func (ec *EquivalenceChecker) bucketSimilarity(a, b PolicyBucket) float64 {
	// Jaccard similarities for lists
	pol := jaccard(a.PolicyURIs, b.PolicyURIs)
	dat := jaccard(a.DataURIs, b.DataURIs)

	// Bonuses
	nameBonus := 0.0
	if len(a.Names) > 0 && len(b.Names) > 0 && overlap(a.Names, b.Names) {
		nameBonus = 0.10
	}
	ruleBonus := 0.0
	if eq, _ := ec.ruleDataEqual(a.RuleData, b.RuleData); eq {
		ruleBonus = 0.10
	}

	// Weight data higher (tends to be more "identity" than policy paths)
	score := 0.40*pol + 0.60*dat + nameBonus + ruleBonus
	return math.Min(score, 1.0)
}

func jaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	set := map[string]struct{}{}
	for _, x := range a {
		set[x] = struct{}{}
	}
	inter := 0
	union := len(set)
	for _, x := range b {
		if _, ok := set[x]; ok {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func overlap(a, b []string) bool {
	set := map[string]struct{}{}
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

func (ec *EquivalenceChecker) compareBucketsWithDifferences(b1, b2 PolicyBucket) []PolicyDifference {
	var diffs []PolicyDifference
	key := ec.bucketKey(b1)

	// policy
	add, rem := ec.diffStringSets(b1.PolicyURIs, b2.PolicyURIs)
	for _, s := range add {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     key,
			Field:         "policy",
			Path:          FieldPath{"policy"},
			Kind:          DiffAdded,
			SuppliedValue: s,
			Summary:       "policy location added",
		})
	}
	for _, s := range rem {
		diffs = append(diffs, PolicyDifference{
			BucketKey: key,
			Field:     "policy",
			Path:      FieldPath{"policy"},
			Kind:      DiffRemoved,
			VSAValue:  s,
			Summary:   "policy location removed",
		})
	}

	// data
	add, rem = ec.diffStringSets(b1.DataURIs, b2.DataURIs)
	for _, s := range add {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     key,
			Field:         "data",
			Path:          FieldPath{"data"},
			Kind:          DiffAdded,
			SuppliedValue: s,
			Summary:       "data location added",
		})
	}
	for _, s := range rem {
		diffs = append(diffs, PolicyDifference{
			BucketKey: key,
			Field:     "data",
			Path:      FieldPath{"data"},
			Kind:      DiffRemoved,
			VSAValue:  s,
			Summary:   "data location removed",
		})
	}

	// include
	add, rem = ec.diffStringSets(b1.Include, b2.Include)
	for _, s := range add {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     key,
			Field:         "include",
			Path:          FieldPath{"include"},
			Kind:          DiffAdded,
			SuppliedValue: s,
			Summary:       "include added",
		})
	}
	for _, s := range rem {
		diffs = append(diffs, PolicyDifference{
			BucketKey: key,
			Field:     "include",
			Path:      FieldPath{"include"},
			Kind:      DiffRemoved,
			VSAValue:  s,
			Summary:   "include removed",
		})
	}

	// exclude
	add, rem = ec.diffStringSets(b1.Exclude, b2.Exclude)
	for _, s := range add {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     key,
			Field:         "exclude",
			Path:          FieldPath{"exclude"},
			Kind:          DiffAdded,
			SuppliedValue: s,
			Summary:       "exclude added",
		})
	}
	for _, s := range rem {
		diffs = append(diffs, PolicyDifference{
			BucketKey: key,
			Field:     "exclude",
			Path:      FieldPath{"exclude"},
			Kind:      DiffRemoved,
			VSAValue:  s,
			Summary:   "exclude removed",
		})
	}

	// ruleData (unified JSON diff)
	eq, err := ec.ruleDataEqual(b1.RuleData, b2.RuleData)
	if err != nil {
		diffs = append(diffs, PolicyDifference{
			BucketKey:     key,
			Field:         "ruleData",
			Path:          FieldPath{"ruleData"},
			Kind:          DiffChanged,
			Summary:       "ruleData compare error",
			VSAValue:      "error",
			SuppliedValue: err.Error(),
		})
	} else if !eq {
		if ud, err := ec.unifiedJSONDiff(b1.RuleData, b2.RuleData); err == nil {
			diffs = append(diffs, PolicyDifference{
				BucketKey:     key,
				Field:         "ruleData",
				Path:          FieldPath{"ruleData"},
				Kind:          DiffChanged,
				Summary:       "ruleData changed",
				SuppliedValue: ud,
			})
		} else {
			diffs = append(diffs, PolicyDifference{
				BucketKey: key,
				Field:     "ruleData",
				Path:      FieldPath{"ruleData"},
				Kind:      DiffChanged,
				Summary:   "ruleData changed (diff unavailable)",
			})
		}
	}

	return diffs
}

func (ec *EquivalenceChecker) describeSource(b PolicyBucket) string {
	switch {
	case len(b.PolicyURIs) > 0 && len(b.DataURIs) > 0:
		return fmt.Sprintf("Policy sources:\n%s\nData sources:\n%s", ec.formatURIs(b.PolicyURIs), ec.formatURIs(b.DataURIs))
	case len(b.PolicyURIs) > 0:
		return fmt.Sprintf("Policy sources:\n%s", ec.formatURIs(b.PolicyURIs))
	case len(b.DataURIs) > 0:
		return fmt.Sprintf("Data sources:\n%s", ec.formatURIs(b.DataURIs))
	default:
		return "Empty policy source"
	}
}

// ---------- Rendering: Git-style unified output ----------

func (ec *EquivalenceChecker) GenerateUnifiedDiffOutput(differences []PolicyDifference) string {
	return ec.GenerateUnifiedDiffOutputWithLabels(differences, "VSA", "Supplied")
}

func (ec *EquivalenceChecker) GenerateUnifiedDiffOutputWithLabels(differences []PolicyDifference, fromLabel, toLabel string) string {
	if len(differences) == 0 {
		return ""
	}

	// Create a copy of differences to avoid modifying the original
	processedDiffs := make([]PolicyDifference, len(differences))
	copy(processedDiffs, differences)

	// Post-process ruleData differences to update their labels
	for i := range processedDiffs {
		if processedDiffs[i].Field == "ruleData" && processedDiffs[i].SuppliedValue != nil {
			if diffStr, ok := processedDiffs[i].SuppliedValue.(string); ok {
				// Replace the hardcoded labels in the ruleData diff
				diffStr = strings.ReplaceAll(diffStr, "--- VSA.ruleData", fmt.Sprintf("--- %s.ruleData", fromLabel))
				diffStr = strings.ReplaceAll(diffStr, "+++ Supplied.ruleData", fmt.Sprintf("+++ %s.ruleData", toLabel))
				processedDiffs[i].SuppliedValue = diffStr
			}
		}
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("--- %s\n", fromLabel))
	buf.WriteString(fmt.Sprintf("+++ %s\n", toLabel))

	// group by source entry
	group := map[string][]PolicyDifference{}
	var keys []string
	for _, d := range processedDiffs {
		if _, ok := group[d.BucketKey]; !ok {
			keys = append(keys, d.BucketKey)
		}
		group[d.BucketKey] = append(group[d.BucketKey], d)
	}
	sort.Strings(keys)

	for _, k := range keys {
		diffs := group[k]
		buf.WriteString(fmt.Sprintf("# source entry: %s\n", k))

		// stable ordering by field then summary
		sort.SliceStable(diffs, func(i, j int) bool {
			if diffs[i].Field == diffs[j].Field {
				return diffs[i].Summary < diffs[j].Summary
			}
			return diffs[i].Field < diffs[j].Field
		})

		for _, d := range diffs {
			ec.writeUnifiedDiffEntry(&buf, d)
		}
	}

	return buf.String()
}

func (ec *EquivalenceChecker) writeUnifiedDiffEntry(buf *strings.Builder, diff PolicyDifference) {
	switch diff.Field {
	case "sources":
		switch diff.Kind {
		case DiffAdded:
			buf.WriteString("+ [source] ")
			if diff.SuppliedValue != nil {
				buf.WriteString(fmt.Sprintf("%v", diff.SuppliedValue))
			}
			buf.WriteString("\n")
		case DiffRemoved:
			buf.WriteString("- [source] ")
			if diff.VSAValue != nil {
				buf.WriteString(fmt.Sprintf("%v", diff.VSAValue))
			}
			buf.WriteString("\n")
		}
	case "policy":
		switch diff.Kind {
		case DiffAdded:
			buf.WriteString(fmt.Sprintf("+ [policy]  %v\n", diff.SuppliedValue))
		case DiffRemoved:
			buf.WriteString(fmt.Sprintf("- [policy]  %v\n", diff.VSAValue))
		}
	case "data":
		switch diff.Kind {
		case DiffAdded:
			buf.WriteString(fmt.Sprintf("+ [data]    %v\n", diff.SuppliedValue))
		case DiffRemoved:
			buf.WriteString(fmt.Sprintf("- [data]    %v\n", diff.VSAValue))
		}
	case "include":
		switch diff.Kind {
		case DiffAdded:
			buf.WriteString(fmt.Sprintf("+ [include] %v\n", diff.SuppliedValue))
		case DiffRemoved:
			buf.WriteString(fmt.Sprintf("- [include] %v\n", diff.VSAValue))
		}
	case "exclude":
		switch diff.Kind {
		case DiffAdded:
			buf.WriteString(fmt.Sprintf("+ [exclude] %v\n", diff.SuppliedValue))
		case DiffRemoved:
			buf.WriteString(fmt.Sprintf("- [exclude] %v\n", diff.VSAValue))
		}
	case "ruleData":
		if diff.Kind == DiffChanged && diff.SuppliedValue != nil {
			// SuppliedValue already contains the unified diff with its own headers
			buf.WriteString(fmt.Sprintf("%s", diff.SuppliedValue))
			if !strings.HasSuffix(fmt.Sprintf("%s", diff.SuppliedValue), "\n") {
				buf.WriteString("\n")
			}
		}
	}
}

// ---------- Helpers ----------

func (ec *EquivalenceChecker) bucketKey(b PolicyBucket) string {
	// Use names if available, otherwise fall back to URIs
	if len(b.Names) > 0 {
		return strings.Join(b.Names, ",")
	}
	return strings.Join(b.PolicyURIs, ",") + "|" + strings.Join(b.DataURIs, ",")
}

func (ec *EquivalenceChecker) diffStringSets(old, new []string) (added, removed []string) {
	a := map[string]struct{}{}
	b := map[string]struct{}{}
	for _, s := range old {
		a[s] = struct{}{}
	}
	for _, s := range new {
		b[s] = struct{}{}
	}
	for s := range b {
		if _, ok := a[s]; !ok {
			added = append(added, s)
		}
	}
	for s := range a {
		if _, ok := b[s]; !ok {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func (ec *EquivalenceChecker) formatURIs(uris []string) string {
	if len(uris) == 0 {
		return "  (none)"
	}
	var out []string
	for _, u := range uris {
		out = append(out, "  - "+u)
	}
	return strings.Join(out, "\n")
}

func (ec *EquivalenceChecker) ruleDataEqual(d1, d2 map[string]interface{}) (bool, error) {
	h1, err := ec.hashRuleData(d1)
	if err != nil {
		return false, err
	}
	h2, err := ec.hashRuleData(d2)
	if err != nil {
		return false, err
	}
	return h1 == h2, nil
}

func (ec *EquivalenceChecker) hashRuleData(d map[string]interface{}) (string, error) {
	cb, err := marshalCanonical(d) // provided by canonical.go
	if err != nil {
		return "", fmt.Errorf("canonicalize ruleData: %w", err)
	}
	sum := sha256.Sum256(cb)
	return fmt.Sprintf("%x", sum), nil
}

func (ec *EquivalenceChecker) unifiedJSONDiff(a, b map[string]interface{}) (string, error) {
	return ec.unifiedJSONDiffWithLabels(a, b, "VSA", "Supplied")
}

func (ec *EquivalenceChecker) unifiedJSONDiffWithLabels(a, b map[string]interface{}, fromLabel, toLabel string) (string, error) {
	// Canonicalize then pretty-print to stabilize whitespace and ordering
	ab, err := marshalCanonical(a)
	if err != nil {
		return "", err
	}
	bb, err := marshalCanonical(b)
	if err != nil {
		return "", err
	}

	var aj, bj map[string]interface{}
	_ = json.Unmarshal(ab, &aj)
	_ = json.Unmarshal(bb, &bj)

	alines, _ := json.MarshalIndent(aj, "", "  ")
	blines, _ := json.MarshalIndent(bj, "", "  ")

	ud := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(alines)),
		B:        difflib.SplitLines(string(blines)),
		FromFile: fmt.Sprintf("%s.ruleData", fromLabel),
		ToFile:   fmt.Sprintf("%s.ruleData", toLabel),
		Context:  2,
	}
	return difflib.GetUnifiedDiffString(ud)
}
