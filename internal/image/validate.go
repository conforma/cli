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

package image

import (
	"context"
	"encoding/json"
	"runtime/trace"
	"sort"
	"time"

	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/qri-io/jsonpointer"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/evaluation_target/application_snapshot_image"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
)

// ValidateImage executes the required method calls to evaluate a given policy
// against a given image url.
func ValidateImage(ctx context.Context, comp app.SnapshotComponent, snap *app.SnapshotSpec, p policy.Policy, evaluators []evaluator.Evaluator, detailed bool) (*output.Output, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:validate-image")
		defer region.End()
		trace.Logf(ctx, "", "image=%q", comp.ContainerImage)
	}

	log.Debugf("Validating image %s", comp.ContainerImage)

	out := &output.Output{ImageURL: comp.ContainerImage, Detailed: detailed, Policy: p}
	a, err := application_snapshot_image.NewApplicationSnapshotImage(ctx, comp, p, *snap)
	if err != nil {
		log.Debug("Failed to create application snapshot image!")
		log.Errorf("DEBUG: NewApplicationSnapshotImage failed for %s: %v", comp.ContainerImage, err)
		return nil, err
	}

	log.Debugf("DEBUG: Checking image accessibility for %s", comp.ContainerImage)
	out.SetImageAccessibleCheckFromError(a.ValidateImageAccess(ctx))
	if !out.ImageAccessibleCheck.Passed {
		log.Errorf("DEBUG: Image not accessible for %s", comp.ContainerImage)
		return out, nil
	}

	if resolved, err := resolveAndSetImageUrl(ctx, comp.ContainerImage, a); err != nil {
		log.Errorf("DEBUG: Failed to resolve image URL for %s: %v", comp.ContainerImage, err)
		return nil, err
	} else {
		out.ImageURL = resolved
		log.Debugf("DEBUG: Resolved image URL to %s", resolved)
	}

	log.Debugf("DEBUG: Fetching image config for %s", comp.ContainerImage)
	if err := a.FetchImageConfig(ctx); err != nil {
		log.Debugf("Unable to fetch image config: %s", err)
		log.Errorf("DEBUG: FetchImageConfig failed for %s: %v", comp.ContainerImage, err)
	}
	if err := a.FetchParentImageConfig(ctx); err != nil {
		log.Debugf("Unable to fetch parent's image config: %s", err)
		log.Errorf("DEBUG: FetchParentImageConfig failed for %s: %v", comp.ContainerImage, err)
	}
	if err := a.FetchImageFiles(ctx); err != nil {
		log.Debugf("Unable to fetch image manifests: %s", err)
		log.Errorf("DEBUG: FetchImageFiles failed for %s: %v", comp.ContainerImage, err)
	}

	log.Debugf("DEBUG: Validating image signature for %s", comp.ContainerImage)
	out.SetImageSignatureCheckFromError(a.ValidateImageSignature(ctx))

	log.Debugf("DEBUG: Validating attestation signature for %s", comp.ContainerImage)
	out.SetAttestationSignatureCheckFromError(a.ValidateAttestationSignature(ctx))
	if !out.AttestationSignatureCheck.Passed {
		log.Errorf("DEBUG: Attestation signature check failed for %s", comp.ContainerImage)
		return out, nil
	}

	out.Signatures = a.Signatures()

	out.Attestations = a.Attestations()

	log.Debugf("DEBUG: Validating attestation syntax for %s", comp.ContainerImage)
	out.SetAttestationSyntaxCheckFromError(a.ValidateAttestationSyntax(ctx))

	if attestationTime := determineAttestationTime(ctx, a.Attestations()); attestationTime != nil {
		p.AttestationTime(*attestationTime)
	}

	att := a.Attestations()
	attCount := len(att)
	out.Attestations = att
	log.Debugf("Found %d attestations", attCount)
	if attCount == 0 {
		log.Errorf("DEBUG: No attestations found for %s", comp.ContainerImage)
		// This is very much a corner case.
		out.SetPolicyCheck([]evaluator.Outcome{
			{
				Failures: []evaluator.Result{{
					Message: "No attestations contain a subject that match the given image.",
				}},
			},
		})
		return out, nil
	}

	log.Debugf("DEBUG: Writing input file for %s", comp.ContainerImage)
	inputPath, inputJSON, err := a.WriteInputFile(ctx)
	if err != nil {
		log.Debug("Problem writing input files!")
		log.Errorf("DEBUG: WriteInputFile failed for %s: %v", comp.ContainerImage, err)
		return nil, err
	}

	var allResults []evaluator.Outcome

	log.Debugf("DEBUG: Running policy evaluation for %s", comp.ContainerImage)
	for _, e := range evaluators {
		// Todo maybe: Handle each one concurrently
		target := evaluator.EvaluationTarget{Inputs: []string{inputPath}}
		if ref := a.ImageReference(ctx); ref == "" {
			log.Debug("Problem getting image reference")
			log.Errorf("DEBUG: ImageReference is empty for %s", comp.ContainerImage)
		} else {
			target.Target = ref
		}

		results, err := e.Evaluate(ctx, target)
		log.Debug("\n\nRunning conftest policy check\n\n")

		if err != nil {
			log.Debug("Problem running conftest policy check!")
			log.Errorf("DEBUG: Policy evaluation failed for %s: %v", comp.ContainerImage, err)
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	out.PolicyInput = inputJSON

	log.Debug("Conftest policy check complete")
	log.Debugf("DEBUG: Setting policy check results for %s", comp.ContainerImage)
	out.SetPolicyCheck(allResults)

	log.Debugf("DEBUG: Validation complete for %s", comp.ContainerImage)
	return out, nil
}

func resolveAndSetImageUrl(ctx context.Context, url string, asi *application_snapshot_image.ApplicationSnapshotImage) (string, error) {
	// Ensure image URL contains a digest to avoid ambiguity in the next
	// validation steps
	ref, err := ParseAndResolve(ctx, url)
	if err != nil {
		log.Debugf("Failed to parse image url %s", url)
		return "", err
	}
	// The original image reference may or may not have had a tag. If it didn't,
	// the code above will set the tag to "latest". This is expected in some cases,
	// e.g. image ref also does not include digest. However, in other cases, although
	// harmless, it may cause confusion to users. The tag is cleared here to prevent
	// such confusion and to further emphasize that the image is only accessed by digest
	// from this point forward.
	ref.Tag = ""
	resolved := ref.String()
	log.Debugf("Resolved image to %s", resolved)

	if err := asi.SetImageURL(resolved); err != nil {
		log.Debugf("Failed to set resolved image url %s", resolved)
		return "", err
	}

	return resolved, nil
}

func determineAttestationTime(ctx context.Context, attestations []attestation.Attestation) *time.Time {
	if len(attestations) == 0 {
		log.Debug("No attestations provided to determine attestation time")
		return nil
	}

	pointer, err := jsonpointer.Parse("/predicate/metadata/buildFinishedOn")
	if err != nil {
		log.Debugf("Failed to parse the fixed JSON Pointer: %v", err)
		panic(err)
	}

	times := make([]time.Time, 0, len(attestations))
	for i, attestation := range attestations {
		data := attestation.Statement()
		obj := map[string]any{}
		if err := json.Unmarshal(data, &obj); err != nil {
			continue
		}
		maybeFinishTime, err := pointer.Eval(obj)
		if err != nil {
			log.Debugf("Failed to evaluate JSON Pointer %s for attestation at %d", pointer, i)
			continue
		}

		finishTime, ok := maybeFinishTime.(string)
		if !ok {
			log.Debugf("Unexpected buildFinishedOn value for attestation at %d: %v", i, maybeFinishTime)
			continue
		}

		time, err := time.Parse(time.RFC3339, finishTime)
		if err != nil {
			log.Debugf("Unable to parse buildFinishedOn `%s` as RFC3339 time of attestation at %d", finishTime, i)
			continue
		}

		times = append(times, time.UTC())
	}

	if len(times) == 0 {
		return nil
	}

	sort.Slice(times, func(i, j int) bool {
		return times[i].After(times[j])
	})

	attestationTime := times[0]

	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("Determined attestation time: %s", attestationTime.Format(time.RFC3339))
	}

	return &attestationTime
}
