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

package evaluator

import (
	"fmt"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
)

// contains include/exclude items
// digestItems stores include/exclude items that are specific with an imageRef
// - the imageRef is the key, value is the policy to include/exclude.
// componentItems stores include/exclude items that are specific to a component name
// - the component name is the key, value is the policy to include/exclude.
// defaultItems are include/exclude items without an imageRef
type Criteria struct {
	digestItems    map[string][]string
	componentItems map[string][]string
	defaultItems   []string
}

func (c *Criteria) len() int {
	totalLength := len(c.defaultItems)
	for _, items := range c.digestItems {
		totalLength += len(items)
	}
	for _, items := range c.componentItems {
		totalLength += len(items)
	}
	return totalLength
}

func (c *Criteria) addItem(key, value string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, value)
	} else {
		if c.digestItems == nil {
			c.digestItems = make(map[string][]string)
		}
		c.digestItems[key] = append(c.digestItems[key], value)
	}
}

func (c *Criteria) addArray(key string, values []string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, values...)
	} else {
		if c.digestItems == nil {
			c.digestItems = make(map[string][]string)
		}
		c.digestItems[key] = append(c.digestItems[key], values...)
	}
}

func (c *Criteria) addComponentItem(componentName, value string) {
	if c.componentItems == nil {
		c.componentItems = make(map[string][]string)
	}
	c.componentItems[componentName] = append(c.componentItems[componentName], value)
}

// This accepts an image ref with digest and optional component name,
// and looks up the image url, digest, and component name separately.
func (c *Criteria) get(imageRef string, componentName string) []string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		log.Debugf("error parsing target image url: %q", imageRef)
		// Return only global defaults if image ref is invalid
		return c.defaultItems
	}

	// Collect keys to look up: always the repository name,
	// and if available, the digest string.
	keys := []string{ref.Context().Name()}
	if digestRef, ok := ref.(name.Digest); ok {
		keys = append(keys, digestRef.DigestStr())
	} else {
		log.Debugf("no digest found for reference: %q", ref)
	}

	var items []string
	for _, k := range keys {
		items = append(items, c.getWithKey(k)...)
	}

	// Add component-specific items if component name is provided
	if componentName != "" {
		if componentItems, ok := c.componentItems[componentName]; ok {
			items = append(items, componentItems...)
		}
	}

	// Add any exceptions that pertain to all images.
	return append(items, c.defaultItems...)
}

func (c *Criteria) getWithKey(key string) []string {
	if items, ok := c.digestItems[key]; ok {
		return items
	}
	return []string{}
}

func computeIncludeExclude(src ecc.Source, p ConfigProvider) (*Criteria, *Criteria) {
	include := &Criteria{}
	exclude := &Criteria{}

	sc := src.Config

	// The lines below take care to make a copy of the includes/excludes slices in order
	// to ensure mutations are not unexpectedly propagated.
	if sc != nil && (len(sc.Include) != 0 || len(sc.Exclude) != 0) {
		include.addArray("", sc.Include)
		exclude.addArray("", sc.Exclude)
	}

	vc := src.VolatileConfig
	if vc != nil {
		include = collectVolatileConfigItems(include, vc.Include, p)
		exclude = collectVolatileConfigItems(exclude, vc.Exclude, p)
	}

	if policyConfig := p.Spec().Configuration; include.len() == 0 && exclude.len() == 0 && policyConfig != nil {
		include.addArray("", policyConfig.Include)
		exclude.addArray("", policyConfig.Exclude)
		// If the old way of specifying collections are used, convert them.
		for _, collection := range policyConfig.Collections {
			include.addItem("", fmt.Sprintf("@%s", collection))
		}
	}

	if include.len() == 0 {
		include.addItem("", "*")
	}

	return include, exclude
}

func collectVolatileConfigItems(items *Criteria, volatileCriteria []ecc.VolatileCriteria, p ConfigProvider) *Criteria {
	at := p.EffectiveTime()
	for _, c := range volatileCriteria {
		from, err := time.Parse(time.RFC3339, c.EffectiveOn)
		if err != nil {
			if c.EffectiveOn != "" {
				log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveOn, err)
			}
			from = at
		}
		until, err := time.Parse(time.RFC3339, c.EffectiveUntil)
		if err != nil {
			if c.EffectiveUntil != "" {
				log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveUntil, err)
			}
			until = at
		}
		if until.Compare(at) >= 0 && from.Compare(at) <= 0 {
			// DEPRECATED: use c.ImageDigest instead
			if c.ImageRef != "" {
				items.addItem(c.ImageRef, c.Value)
			} else if c.ImageUrl != "" {
				items.addItem(c.ImageUrl, c.Value)
			} else if c.ImageDigest != "" {
				items.addItem(c.ImageDigest, c.Value)
			} else if len(c.ComponentNames) > 0 {
				for _, componentName := range c.ComponentNames {
					items.addComponentItem(string(componentName), c.Value)
				}
			} else {
				items.addItem("", c.Value)
			}
		}
	}

	return items
}
