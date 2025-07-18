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

package tracker

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/stuart-warren/yamlfmt"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/image"
)

const ociPrefix = "oci://"

type taskRecord struct {
	Ref string `json:"ref"`
	// ExpiresOn should be omitted if there isn't a value. Not using a pointer means it will always
	// have a value, e.g. 0001-01-01T00:00:00Z.
	ExpiresOn  *time.Time `json:"expires_on,omitempty"`
	Tag        string     `json:"-"`
	Repository string     `json:"-"`
}

type Tracker struct {
	TrustedTasks map[string][]taskRecord `json:"trusted_tasks,omitempty"`
}

// newTracker returns a new initialized instance of Tracker. If path
// is "", an empty instance is returned.
func newTracker(input []byte) (t Tracker, err error) {
	if input != nil {
		err = yaml.Unmarshal(input, &t)
		if err != nil {
			return
		}
	} else {
		t = Tracker{}
	}

	t.setDefaults()
	return
}

// setDefaults initializes the required nested attributes.
func (t *Tracker) setDefaults() {
	if t.TrustedTasks == nil {
		t.TrustedTasks = map[string][]taskRecord{}
	}
}

// addTrustedTaskRecord includes the given Tekton bundle Task record in the tracker.
func (t *Tracker) addTrustedTaskRecord(prefix string, record taskRecord) {
	newRecords := []taskRecord{record}
	var group string
	if record.Tag == "" {
		group = fmt.Sprintf("%s%s", prefix, record.Repository)
	} else {
		group = fmt.Sprintf("%s%s:%s", prefix, record.Repository, record.Tag)
	}
	if _, ok := t.TrustedTasks[group]; !ok {
		t.TrustedTasks[group] = newRecords
	} else {
		t.TrustedTasks[group] = append(newRecords, t.TrustedTasks[group]...)
	}
}

// Output serializes the Tracker state as YAML
func (t Tracker) Output() ([]byte, error) {
	out, err := yaml.Marshal(t)
	if err != nil {
		return nil, err
	}

	// sorts the YAML document making it deterministic
	return yamlfmt.Format(bytes.NewBuffer(out), true)
}

var oneDay = time.Hour * 24

// Track implements the common workflow of loading an existing tracker file and adding
// records to one of its collections.
// Each url is expected to reference a valid Tekton bundle. Each bundle may be added
// to none, 1, or 2 collections depending on the Tekton resource types they include.
func Track(ctx context.Context, urls []string, input []byte, prune bool, freshen bool, inEffectDays int) ([]byte, error) {
	t, err := newTracker(input)
	if err != nil {
		return nil, err
	}

	imageUrls, gitUrls := groupUrls(urls)

	// Note: inEffectDays parameter is kept for backward compatibility but no longer used
	// Records now use creation timestamps instead of future effective dates

	if err := t.trackImageReferences(ctx, imageUrls, freshen); err != nil {
		return nil, err
	}

	if err := t.trackGitReferences(ctx, gitUrls, freshen); err != nil {
		return nil, err
	}

	t.filterBundles(prune)

	t.setExpiration(inEffectDays)

	return t.Output()
}

func groupUrls(urls []string) ([]string, []string) {
	imgs := make([]string, 0, len(urls))
	gits := make([]string, 0, len(urls))
	for _, u := range urls {
		if strings.HasPrefix(u, "git+") {
			gits = append(gits, u)
		} else {
			imgs = append(imgs, u)
		}
	}

	return imgs, gits
}

func (t *Tracker) trackImageReferences(ctx context.Context, urls []string, freshen bool) error {
	refs, err := image.ParseAndResolveAll(ctx, urls, name.StrictValidation)
	if err != nil {
		return err
	}

	if freshen {
		log.Debug("Freshen is enabled")
		imageRefs, err := inputBundleTags(ctx, *t)
		if err != nil {
			return err
		}

		refs = append(refs, imageRefs...)
	}

	for _, ref := range refs {
		log.Debugf("Processing bundle %q", ref.String())
		hasTask, err := containsTask(ctx, ref)
		if err != nil {
			return err
		}

		if hasTask {
			t.addTrustedTaskRecord(ociPrefix, taskRecord{
				Ref:        ref.Digest,
				Tag:        ref.Tag,
				Repository: ref.Repository,
			})
		}
	}

	return nil
}

func (t *Tracker) trackGitReferences(ctx context.Context, urls []string, freshen bool) error {
	if freshen {
		log.Debug("Freshen is enabled")

		tmp := make([]string, len(urls), len(urls)+len(t.TrustedTasks))
		copy(tmp, urls)
		urls = tmp
		for u := range t.TrustedTasks {
			if strings.HasPrefix(u, "git+") {
				urls = append(urls, u)
			}
		}
	}

	g := NewGitTracker()
	defer g.Close(ctx)

	for _, u := range urls {
		schemeSepIdx := strings.Index(u, "//")
		pathSepIdx := strings.LastIndex(u, "//")

		if pathSepIdx <= schemeSepIdx {
			return fmt.Errorf("expected %q to contain the `//` to separate the repository from the path, e.g. git+https://github.com/org/repository//task/0.1/task.yaml@f0cacc1a", u)
		}

		repository := u[0:pathSepIdx]
		rest := u[pathSepIdx+2:]

		path, rev, found := strings.Cut(rest, "@")
		if !found {
			if !freshen {
				return fmt.Errorf("expected %q to contain the revision information following the `@`, e.g. git+https://github.com/org/repository//task/0.1/task.yaml@f0cacc1a, to fetch the latest revision from a remote URL provide the --freshen parameter", u)
			}
			var err error
			rev, err = g.GitResolve(ctx, repository, rest)
			if err != nil {
				return err
			}
			path = rest
		} else if freshen {
			// nothing prevents the user using --freshen and revision, so log what revision is being used.
			log.Debugf("--freshen used, but a revision is also provided. Using provided revision: %q", rev)
		}

		t.addTrustedTaskRecord("", taskRecord{
			Repository: fmt.Sprintf("%s//%s", repository, path),
			Ref:        rev,
		})
	}

	return nil
}

func inputBundleTags(ctx context.Context, t Tracker) ([]image.ImageReference, error) {
	uniqueTagRefs := map[string]bool{}

	for group := range t.TrustedTasks {
		tagRef := ociRefFromGroup(group)
		if tagRef == "" {
			// Not an OCI bundle
			continue
		}
		uniqueTagRefs[tagRef] = true
	}

	tagRefs := make([]string, 0, len(uniqueTagRefs))
	for bundle := range uniqueTagRefs {
		tagRefs = append(tagRefs, bundle)
	}

	return image.ParseAndResolveAll(ctx, tagRefs, name.StrictValidation)
}

// filterBundles applies filterRecords to TaskBundles.
func (t *Tracker) filterBundles(prune bool) {
	for group, records := range t.TrustedTasks {
		log.Debugf("Filtering task records for %q", group)
		t.TrustedTasks[group] = filterRecords(records, prune)
	}
}

// filterRecords reduces the list of records by removing superfluous entries.
// It removes records that have the same reference in a certain group. If prune is
// true, it removes records that have already expired based on their expires_on date.
func filterRecords(records []taskRecord, prune bool) []taskRecord {
	now := time.Now().UTC()

	// lastRef tracks the latest ref seen. This is used to remove consecutive entries with the
	// same digest.
	var lastRef string
	unique := make([]taskRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		// NOTE: Newly added records will have a repository, but existing ones
		// will not. This is expected because the output does not persist the
		// repository for each record. Instead, the repository is the attribute
		// which references the list of records.
		r := records[i]

		if lastRef == r.Ref {
			continue
		}
		lastRef = r.Ref

		unique = append([]taskRecord{r}, unique...)
	}

	var relevant []taskRecord
	if prune {
		for _, r := range unique {
			// Keep records that haven't expired yet, or records with no expiration date
			if r.ExpiresOn == nil || now.Before(*r.ExpiresOn) {
				relevant = append(relevant, r)
			}
		}
	} else {
		relevant = unique
	}

	filteredCount := len(records) - len(relevant)
	if filteredCount != 0 {
		log.Debugf("Filtered %d records (prune=%t)", filteredCount, prune)
	}
	return relevant
}

// setExpiration sets the expires_on attribute on records using a duration-based approach.
// Each record expires after a configurable duration based on inEffectDays from when it's added.
// The most recent record (index 0) gets no expiration date, making it the current active record.
func (t *Tracker) setExpiration(inEffectDays int) {
	expirationDuration := time.Duration(inEffectDays) * oneDay // Use --in-effect-days flag value
	now := time.Now().UTC().Round(oneDay)

	for _, records := range t.TrustedTasks {
		for i := range records {
			if i == 0 {
				// Most recent record doesn't expire
				records[i].ExpiresOn = nil
			} else {
				// Older records expire after the duration
				expiresOn := now.Add(expirationDuration)
				records[i].ExpiresOn = &expiresOn
			}
		}
	}
}

// ociRefFromGroup returns the OCI image reference from the given group, e.g.
// oci://registry.local/spam:latest -> registry.local/spam:latest
// If the group does not represent an OCI image reference, an empty string is returned.
func ociRefFromGroup(group string) string {
	if !strings.HasPrefix(group, ociPrefix) {
		// Not an OCI bundle
		return ""
	}
	return strings.TrimPrefix(group, ociPrefix)
}
