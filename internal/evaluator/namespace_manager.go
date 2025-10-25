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
	"context"

	log "github.com/sirupsen/logrus"
)

// NamespaceManager handles namespace filtering and resolution for policy evaluation.
type NamespaceManager struct {
	policyResolver PolicyResolver
	namespace      []string
}

// NewNamespaceManager creates a new NamespaceManager instance.
func NewNamespaceManager(policyResolver PolicyResolver, namespace []string) *NamespaceManager {
	return &NamespaceManager{
		policyResolver: policyResolver,
		namespace:      namespace,
	}
}

// NamespaceResolution contains the resolved namespace configuration.
type NamespaceResolution struct {
	NamespacesToUse []string
	AllNamespaces   bool
}

// ResolveNamespaces determines which namespaces should be used for evaluation.
func (nm *NamespaceManager) ResolveNamespaces(
	ctx context.Context,
	allRules policyRules,
	target string,
) NamespaceResolution {
	var filteredNamespaces []string

	if nm.policyResolver != nil {
		// Use unified policy resolution
		policyResolution := nm.policyResolver.ResolvePolicy(allRules, target)

		// Extract included package names for conftest evaluation
		for pkg := range policyResolution.IncludedPackages {
			filteredNamespaces = append(filteredNamespaces, pkg)
		}

		log.Debugf("Policy resolution: %d packages included",
			len(policyResolution.IncludedPackages))
		log.Debugf("Policy resolution details: included=%v",
			policyResolution.IncludedPackages)
	} else {
		// Legacy filtering approach - use the old namespace filtering logic
		log.Debugf("Using legacy filtering approach")
	}

	// Determine which namespaces to use
	namespacesToUse := nm.namespace
	allNamespaces := false

	// If we have filtered namespaces from the filtering system, use those
	if len(filteredNamespaces) > 0 {
		namespacesToUse = filteredNamespaces
	} else if len(namespacesToUse) == 0 {
		// For new filtering with empty namespaces, also evaluate all namespaces
		// This ensures backward compatibility with tests that don't specify namespaces
		allNamespaces = true
	}

	log.Debugf("Namespaces to use: %v, allNamespaces: %v", namespacesToUse, allNamespaces)

	return NamespaceResolution{
		NamespacesToUse: namespacesToUse,
		AllNamespaces:   allNamespaces,
	}
}
