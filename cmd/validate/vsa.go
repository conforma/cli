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
	"sort"
	"strings"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/google/go-containerregistry/pkg/name"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
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
		outputFile          string
		strict              bool
		effectiveTime       string
		spec                *app.SnapshotSpec
		workers             int
		noColor             bool
		forceColor          bool
	}{
		strict:        true,
		effectiveTime: policy.Now,
		workers:       5,
	}

	validOutputFormats := []string{"json", "yaml", "text"}

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

			Write output in JSON format to a file:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml --output json=results.json

			Write output in YAML format to stdout and in JSON format to a file:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml --output yaml --output json=results.json
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
				if s, _, err := applicationsnapshot.DetermineInputSpecWithExpansion(ctx, applicationsnapshot.Input{
					Image:  data.imageRef,
					Images: data.images,
				}, true); err != nil {
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

	cmd.Flags().StringSliceVar(&data.output, "output", data.output, hd.Doc(`
		write output to a file in a specific format. Use empty string path for stdout.
		May be used multiple times. Possible formats are:
		`+strings.Join(validOutputFormats, ", ")+`. In following format and file path
		additional options can be provided in key=value form following the question
		mark (?) sign, for example: --output text=output.txt?show-successes=false
	`))

	cmd.Flags().StringVarP(&data.outputFile, "output-file", "o", data.outputFile,
		"[DEPRECATED] write output to a file. Use empty string for stdout, default behavior")

	cmd.Flags().BoolVar(&data.strict, "strict", true, "Exit with non-zero code if validation fails")
	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, "Effective time for policy evaluation")
	cmd.Flags().IntVar(&data.workers, "workers", 5, "Number of worker threads for parallel processing")

	cmd.Flags().BoolVar(&data.noColor, "no-color", false, "Disable color when using text output even when the current terminal supports it")
	cmd.Flags().BoolVar(&data.forceColor, "color", false, "Enable color when using text output even when the current terminal does not support it")

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
	outputFile          string
	strict              bool
	effectiveTime       string
	spec                *app.SnapshotSpec
	workers             int
	noColor             bool
	forceColor          bool
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
	fmt.Printf("VSA predicate: %+v\n", predicate)
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

	// Create VSA component
	component := applicationsnapshot.VSAComponent{
		Name:              "vsa-file",
		ContainerImage:    imageRef,
		Success:           validationResult.Passed,
		FailingRulesCount: len(validationResult.FailingRules),
		MissingRulesCount: len(validationResult.MissingRules),
	}

	// Extract violations from validation result
	violations := make([]applicationsnapshot.VSAViolation, 0)
	for _, rule := range validationResult.FailingRules {
		violation := applicationsnapshot.VSAViolation{
			RuleID:      rule.RuleID,
			ImageRef:    imageRef,
			Reason:      rule.Reason,
			Title:       rule.Title,
			Description: rule.Description,
			Solution:    rule.Solution,
		}
		violations = append(violations, violation)
	}

	// Create VSA report
	report := applicationsnapshot.NewVSAReport([]applicationsnapshot.VSAComponent{component}, violations)

	// Handle output
	if len(data.outputFile) > 0 {
		data.output = append(data.output, fmt.Sprintf("%s=%s", "json", data.outputFile))
	}

	// Use the format system for output
	p := format.NewTargetParser("json", format.Options{}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
	utils.SetColorEnabled(data.noColor, data.forceColor)

	if err := writeVSAReport(report, data.output, p); err != nil {
		return err
	}

	if data.strict && !report.Success {
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
	outputFile          string
	strict              bool
	effectiveTime       string
	spec                *app.SnapshotSpec
	workers             int
	noColor             bool
	forceColor          bool
}, validate vsaValidationFunc) error {
	type result struct {
		err              error
		component        app.SnapshotComponent
		validationResult *vsa.ValidationResult
		vsaComponents    []applicationsnapshot.Component // Actual components from VSA attestation
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
				results <- result{err: err, component: comp, validationResult: nil, vsaComponents: nil}
				if task != nil {
					task.End()
				}
				continue
			}
			digest := ref.Identifier()

			rekorRetriever, err := vsa.NewRekorVSADataRetriever(vsa.DefaultRetrievalOptions(), digest)
			if err != nil {
				err = fmt.Errorf("failed to create Rekor retriever for %s: %w", comp.ContainerImage, err)
				results <- result{err: err, component: comp, validationResult: nil, vsaComponents: nil}
				if task != nil {
					task.End()
				}
				continue
			}

			// Call the validation function
			validationResult, err := validate(ctx, comp.ContainerImage, data.policy, rekorRetriever, data.publicKey)
			if err != nil {
				err = fmt.Errorf("validation failed for %s: %w", comp.ContainerImage, err)
				results <- result{err: err, component: comp, validationResult: nil, vsaComponents: nil}
				if task != nil {
					task.End()
				}
				continue
			}

			// Extract actual components from VSA attestation data
			var vsaComponents []applicationsnapshot.Component
			if validationResult != nil {
				// Try to retrieve VSA data to extract actual components
				vsaContent, err := rekorRetriever.RetrieveVSAData(ctx)
				if err == nil {
					predicate, err := vsa.ParseVSAContent(vsaContent)
					if err == nil && predicate.Results != nil {
						// Use actual components from VSA attestation if available
						vsaComponents = predicate.Results.Components
						logrus.Debugf("Extracted %d actual components from VSA attestation for %s", len(vsaComponents), comp.ContainerImage)
					}
				}
			}

			if task != nil {
				task.End()
			}

			results <- result{err: nil, component: comp, validationResult: validationResult, vsaComponents: vsaComponents}
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

	var allErrors error
	var componentResults []result

	// Collect all results
	for i := 0; i < numComponents; i++ {
		r := <-results
		componentResults = append(componentResults, r)
		if r.err != nil {
			allErrors = errors.Join(allErrors, r.err)
		}
	}
	close(results)

	// Convert results to VSA components, using actual components from VSA attestation when available
	var vsaComponents []applicationsnapshot.VSAComponent
	var allViolations []applicationsnapshot.VSAViolation

	for _, r := range componentResults {
		// Determine which components to use for this result
		var componentsToProcess []applicationsnapshot.Component

		if len(r.vsaComponents) > 0 {
			// Use actual components from VSA attestation
			componentsToProcess = r.vsaComponents
			logrus.Debugf("Using %d actual components from VSA attestation for %s", len(componentsToProcess), r.component.ContainerImage)
		} else {
			// Fallback to snapshot component if no VSA components available
			componentsToProcess = []applicationsnapshot.Component{
				{
					SnapshotComponent: r.component,
				},
			}
			logrus.Debugf("Using snapshot component as fallback for %s", r.component.ContainerImage)
		}

		// Process each component
		for _, comp := range componentsToProcess {
			component := applicationsnapshot.VSAComponent{
				Name:           comp.Name,
				ContainerImage: comp.ContainerImage,
			}

			if r.err != nil {
				component.Success = false
				component.Error = r.err.Error()
			} else if r.validationResult != nil {
				component.Success = r.validationResult.Passed
				component.FailingRulesCount = len(r.validationResult.FailingRules)
				component.MissingRulesCount = len(r.validationResult.MissingRules)
			} else {
				component.Success = false
				component.Error = "no validation result available"
			}

			vsaComponents = append(vsaComponents, component)
		}

		// Extract violations from validation result
		if r.validationResult != nil {
			for _, rule := range r.validationResult.FailingRules {
				// For violations, we need to determine which component image to associate with
				// If we have actual VSA components, use the component image from the rule if available
				// Otherwise, fall back to the snapshot component image
				imageRef := r.component.ContainerImage
				if rule.ComponentImage != "" {
					imageRef = rule.ComponentImage
				}

				violation := applicationsnapshot.VSAViolation{
					RuleID:      rule.RuleID,
					ImageRef:    imageRef,
					Reason:      rule.Reason,
					Title:       rule.Title,
					Description: rule.Description,
					Solution:    rule.Solution,
				}
				allViolations = append(allViolations, violation)
			}
		}
	}

	// Ensure some consistency in output.
	sort.Slice(vsaComponents, func(i, j int) bool {
		return vsaComponents[i].ContainerImage > vsaComponents[j].ContainerImage
	})

	// Create VSA report
	report := applicationsnapshot.NewVSAReport(vsaComponents, allViolations)

	// Handle output
	if len(data.outputFile) > 0 {
		data.output = append(data.output, fmt.Sprintf("%s=%s", "json", data.outputFile))
	}

	// Use the format system for output
	p := format.NewTargetParser("json", format.Options{}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
	utils.SetColorEnabled(data.noColor, data.forceColor)

	if err := writeVSAReport(report, data.output, p); err != nil {
		return err
	}

	if data.strict && !report.Success {
		if allErrors != nil {
			return fmt.Errorf("validation failed: %w", allErrors)
		}
		return errors.New("success criteria not met")
	}

	return allErrors
}

// writeVSAReport writes the VSA report using the format system
func writeVSAReport(report applicationsnapshot.VSAReport, targets []string, p format.TargetParser) error {
	return applicationsnapshot.WriteVSAReport(report, targets, p)
}
