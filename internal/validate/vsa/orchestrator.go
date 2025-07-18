// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"context"
	"fmt"
)

// GenerateAndWriteVSA generates a VSA predicate and writes it to a file, returning the written path.
func GenerateAndWriteVSA[T any](ctx context.Context, generator PredicateGenerator[T], writer PredicateWriter[T]) (string, error) {
	pred, err := generator.GeneratePredicate(ctx)
	if err != nil {
		return "", err
	}
	writtenPath, err := writer.WritePredicate(pred)
	if err != nil {
		return "", err
	}
	return writtenPath, nil
}

// AttestVSA handles VSA attestation and envelope writing for the target component.
func AttestVSA(ctx context.Context, attestor PredicateAttestor) (string, error) {
	env, err := attestor.AttestPredicate(ctx)
	if err != nil {
		return "", fmt.Errorf("[VSA] Error attesting VSA for artifact %s: %w", attestor.TargetDigest(), err)
	}
	envelopePath, err := attestor.WriteEnvelope(env)
	if err != nil {
		return "", fmt.Errorf("[VSA] Error writing envelope for artifact %s: %w", attestor.TargetDigest(), err)
	}
	return envelopePath, nil
}
