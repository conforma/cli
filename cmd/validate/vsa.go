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

package validate

import (
	"context"
	"errors"
	"fmt"
	"runtime/trace"

	hd "github.com/MakeNowJust/heredoc"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/cobra"

	"encoding/json"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
)

type vsaValidationFunc func(context.Context, string, policy.Policy, vsa.VSADataRetriever, string) (*vsa.ValidationResult, error)

func validateVSACmd(validate vsaValidationFunc) *cobra.Command {
	data := struct {
		imageRef            string
		images              string
		policyConfiguration string
		policy              policy.Policy
		vsaPath             string
		publicKey           string
		output              []string
		strict              bool
		effectiveTime       string
		spec                *app.SnapshotSpec
		workers             int
	}{
		strict:        true,
		effectiveTime: policy.Now,
		workers:       5,
	}

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Validate VSA (Vulnerability Scanning Artifacts) against policies",

		Long: hd.Doc(`
			Validate VSA records against the provided policies.
			
			If --vsa is provided, reads VSA from the specified file.
			If --vsa is omitted, retrieves VSA records from Rekor using the image digest.
			
			Can validate a single image with --image or multiple images from an ApplicationSnapshot
			with --images.
		`),

		Example: hd.Doc(`
			Validate VSA from file for a single image:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml --vsa ./vsa.json
			
			Validate VSA from Rekor for a single image:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml
			
			Validate VSA for multiple images from ApplicationSnapshot file:
			  ec validate vsa --images my-app.yaml --policy .ec/policy.yaml
			
			Validate VSA for multiple images from inline ApplicationSnapshot:
			  ec validate vsa --images '{"components":[{"containerImage":"quay.io/acme/app@sha256:..."}]}' --policy .ec/policy.yaml
		`),

		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()
			if trace.IsEnabled() {
				var task *trace.Task
				ctx, task = trace.NewTask(ctx, "ec:validate-vsa-prepare")
				defer task.End()
				cmd.SetContext(ctx)
			}

			// Validate input: either image/images OR vsa path must be provided
			if data.imageRef == "" && data.images == "" && data.vsaPath == "" {
				return errors.New("either --image/--images OR --vsa must be provided")
			}

			// Load policy configuration if provided
			if data.policyConfiguration != "" {
				policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
				if err != nil {
					return fmt.Errorf("failed to load policy configuration: %w", err)
				}

				// Create policy options
				policyOptions := policy.Options{
					EffectiveTime: data.effectiveTime,
					PolicyRef:     policyConfiguration,
					PublicKey:     data.publicKey,
				}

				// Load the policy
				if p, _, err := policy.PreProcessPolicy(ctx, policyOptions); err != nil {
					return fmt.Errorf("failed to load policy: %w", err)
				} else {
					data.policy = p
				}
			} else {
				// No policy provided - this is allowed for testing
				data.policy = nil
			}

			// Determine input spec from various sources (image, images, etc.)
			if data.imageRef != "" || data.images != "" {
				if s, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
					Image:  data.imageRef,
					Images: data.images,
				}); err != nil {
					return fmt.Errorf("determine input spec: %w", err)
				} else {
					data.spec = s
				}
			}

			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if trace.IsEnabled() {
				var task *trace.Task
				ctx, task = trace.NewTask(ctx, "ec:validate-vsa")
				defer task.End()
				cmd.SetContext(ctx)
			}

			// If VSA path is provided, validate the VSA file directly
			if data.vsaPath != "" {
				return validateVSAFile(ctx, cmd, data, validate)
			}

			// If image/ApplicationSnapshot is provided, find VSAs from Rekor and validate
			if data.spec != nil {
				return validateImagesFromRekor(ctx, cmd, data, validate)
			}

			return errors.New("no input provided for validation")
		},
	}

	// Add flags with required validation
	cmd.Flags().StringVarP(&data.imageRef, "image", "i", "", "OCI image reference")
	cmd.Flags().StringVar(&data.images, "images", "", "path to ApplicationSnapshot Spec JSON file or JSON representation of an ApplicationSnapshot Spec")

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", "", "Policy configuration (optional for testing)")

	cmd.Flags().StringVarP(&data.vsaPath, "vsa", "", "", "Path to VSA file (optional - if omitted, retrieves from Rekor)")
	cmd.Flags().StringVarP(&data.publicKey, "public-key", "", "", "Public key for VSA signature verification")
	cmd.Flags().StringSliceVarP(&data.output, "output", "o", []string{"yaml"}, "Output format (json, yaml)")
	cmd.Flags().BoolVar(&data.strict, "strict", true, "Exit with non-zero code if validation fails")
	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, "Effective time for policy evaluation")
	cmd.Flags().IntVar(&data.workers, "workers", 5, "Number of worker threads for parallel processing")

	return cmd
}

// validateVSAFile handles validation when a VSA file path is provided
func validateVSAFile(ctx context.Context, cmd *cobra.Command, data struct {
	imageRef            string
	images              string
	policyConfiguration string
	policy              policy.Policy
	vsaPath             string
	publicKey           string
	output              []string
	strict              bool
	effectiveTime       string
	spec                *app.SnapshotSpec
	workers             int
}, validate vsaValidationFunc) error {
	// Create file-based retriever
	fs := utils.FS(ctx)
	retriever := vsa.NewFileVSADataRetriever(fs, data.vsaPath)

	// For VSA file validation, we need to extract the image reference from the VSA content
	vsaContent, err := retriever.RetrieveVSAData(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve VSA data: %w", err)
	}

	// Parse VSA content to extract image reference
	predicate, err := vsa.ParseVSAContent(vsaContent)
	if err != nil {
		return fmt.Errorf("failed to parse VSA content: %w", err)
	}

	// Use the image reference from the VSA predicate
	imageRef := predicate.ImageRef
	if imageRef == "" {
		return fmt.Errorf("VSA does not contain an image reference")
	}

	// Validate the VSA
	validationResult, err := validate(ctx, imageRef, data.policy, retriever, data.publicKey)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Output results
	outputResults(validationResult, data.output)

	if data.strict && !validationResult.Passed {
		return errors.New("success criteria not met")
	}

	return nil
}

// validateImagesFromRekor handles validation when image references are provided (finds VSAs from Rekor)
func validateImagesFromRekor(ctx context.Context, cmd *cobra.Command, data struct {
	imageRef            string
	images              string
	policyConfiguration string
	policy              policy.Policy
	vsaPath             string
	publicKey           string
	output              []string
	strict              bool
	effectiveTime       string
	spec                *app.SnapshotSpec
	workers             int
}, validate vsaValidationFunc) error {
	type result struct {
		err              error
		component        app.SnapshotComponent
		validationResult *vsa.ValidationResult
	}

	appComponents := data.spec.Components
	numComponents := len(appComponents)

	// Set numWorkers to the value from our flag. The default is 5.
	numWorkers := data.workers

	// worker is responsible for processing one component at a time from the jobs channel,
	// and for emitting a corresponding result for the component on the results channel.
	worker := func(id int, jobs <-chan app.SnapshotComponent, results chan<- result) {
		logrus.Debugf("Starting VSA worker %d", id)
		for comp := range jobs {
			ctx := cmd.Context()
			var task *trace.Task
			if trace.IsEnabled() {
				ctx, task = trace.NewTask(ctx, "ec:validate-vsa-component")
				trace.Logf(ctx, "", "workerID=%d", id)
			}

			logrus.Debugf("VSA Worker %d got a component %q", id, comp.ContainerImage)

			// Use Rekor-based retriever to find VSA for this component
			ref, err := name.ParseReference(comp.ContainerImage)
			if err != nil {
				err = fmt.Errorf("invalid image reference %s: %w", comp.ContainerImage, err)
				results <- result{err: err, component: comp, validationResult: nil}
				if task != nil {
					task.End()
				}
				continue
			}
			digest := ref.Identifier()

			rekorRetriever, err := vsa.NewRekorVSADataRetriever(vsa.DefaultRetrievalOptions(), digest)
			if err != nil {
				err = fmt.Errorf("failed to create Rekor retriever for %s: %w", comp.ContainerImage, err)
				results <- result{err: err, component: comp, validationResult: nil}
				if task != nil {
					task.End()
				}
				continue
			}

			// Call the validation function
			validationResult, err := validate(ctx, comp.ContainerImage, data.policy, rekorRetriever, data.publicKey)
			if err != nil {
				err = fmt.Errorf("validation failed for %s: %w", comp.ContainerImage, err)
				results <- result{err: err, component: comp, validationResult: nil}
				if task != nil {
					task.End()
				}
				continue
			}

			if task != nil {
				task.End()
			}

			results <- result{err: nil, component: comp, validationResult: validationResult}
		}
		logrus.Debugf("Done with VSA worker %d", id)
	}

	jobs := make(chan app.SnapshotComponent, numComponents)
	results := make(chan result, numComponents)

	// Initialize each worker. They will wait patiently until a job is sent to the jobs
	// channel, or the jobs channel is closed.
	for i := 0; i < numWorkers; i++ {
		go worker(i, jobs, results)
	}

	// Initialize all the jobs. Each worker will pick a job from the channel when the worker
	// is ready to consume a new job.
	for _, c := range appComponents {
		jobs <- c
	}
	close(jobs)

	allPassed := true
	var allErrors error
	var componentResults []result

	// Collect all results
	for i := 0; i < numComponents; i++ {
		r := <-results
		componentResults = append(componentResults, r)
		if r.err != nil {
			allErrors = errors.Join(allErrors, r.err)
			allPassed = false
		} else if r.validationResult == nil {
			allPassed = false
		} else if !r.validationResult.Passed {
			allPassed = false
		}
	}
	close(results)

	// Output results for each component
	for _, r := range componentResults {
		if r.err != nil {
			// Output error for this component
			if len(data.output) > 0 {
				fmt.Printf("=== Validation Results for %s ===\n", r.component.ContainerImage)
				fmt.Printf("Error: %v\n\n", r.err)
			}
			continue
		}

		// Output the result for this component
		if len(data.output) > 0 {
			fmt.Printf("=== Validation Results for %s ===\n", r.component.ContainerImage)
			outputResults(r.validationResult, data.output)
			fmt.Println()
		}
	}

	if data.strict && !allPassed {
		if allErrors != nil {
			return fmt.Errorf("validation failed: %w", allErrors)
		}
		return errors.New("success criteria not met")
	}

	return allErrors
}

// outputResults outputs validation results in the specified format
func outputResults(validationResult *vsa.ValidationResult, outputFormats []string) {
	for _, outputFormat := range outputFormats {
		switch outputFormat {
		case "json":
			jsonData, err := json.MarshalIndent(validationResult, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling to JSON: %v\n", err)
				continue
			}
			fmt.Println(string(jsonData))
		case "yaml":
			// Simple YAML-like output
			fmt.Printf("Passed: %t\n", validationResult.Passed)
			fmt.Printf("Signature Verified: %t\n", validationResult.SignatureVerified)
			fmt.Printf("Summary: %s\n", validationResult.Summary)
			fmt.Printf("Image Digest: %s\n", validationResult.ImageDigest)
			fmt.Printf("Passing Count: %d\n", validationResult.PassingCount)
			fmt.Printf("Total Required: %d\n", validationResult.TotalRequired)

			if len(validationResult.MissingRules) > 0 {
				fmt.Printf("Missing Rules: %d\n", len(validationResult.MissingRules))
				for _, rule := range validationResult.MissingRules {
					fmt.Printf("  - %s (%s): %s\n", rule.RuleID, rule.Package, rule.Reason)
				}
			}

			if len(validationResult.FailingRules) > 0 {
				fmt.Printf("Failing Rules: %d\n", len(validationResult.FailingRules))
				for _, rule := range validationResult.FailingRules {
					fmt.Printf("  - %s (%s): %s - %s\n", rule.RuleID, rule.Package, rule.Message, rule.Reason)
				}
			}
		default:
			fmt.Printf("Unsupported output format: %s\n", outputFormat)
		}
	}
}
