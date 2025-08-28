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

package applicationsnapshot

// ExpansionInfo tracks the relationships between image indexes and their child manifests
// that are created when expanding multi-arch images.
type ExpansionInfo struct {
	// ChildrenByIndex maps an image index digest to the list of child manifest digests
	ChildrenByIndex map[string][]string `json:"childrenByIndex,omitempty"`
	// ParentByChild maps a child manifest digest to its parent index digest
	ParentByChild map[string]string `json:"parentByChild,omitempty"`
	// IndexAliases maps image references to their pinned digest form
	IndexAliases map[string]string `json:"indexAliases,omitempty"`
}

// NewExpansionInfo creates a new ExpansionInfo instance
func NewExpansionInfo() *ExpansionInfo {
	return &ExpansionInfo{
		ChildrenByIndex: make(map[string][]string),
		ParentByChild:   make(map[string]string),
		IndexAliases:    make(map[string]string),
	}
}
