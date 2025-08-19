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
	"encoding/json"
	"errors"
	"fmt"
	"runtime/trace"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/validate/vsa"
)

type vsaValidationFunc func(context.Context, string, policy.Policy, vsa.VSADataRetriever, string) (*vsa.ValidationResult, error)

func validateVSACmd(validate vsaValidationFunc) *cobra.Command {
	data := struct {
		imageRef            string
		policyConfiguration string
		policy              policy.Policy
		vsaPath             string
		publicKey           string
		output              []string
		outputFile          string
		strict              bool
		noColor             bool
		forceColor          bool
	}{
		strict: true,
	}

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Validate VSA (Vulnerability Scanning Artifacts) against policies",

		Long: hd.Doc(`
			Validate VSA records against the provided policies.
			
			If --vsa is provided, reads VSA from the specified file.
			If --vsa is omitted, retrieves VSA records from Rekor using the image digest.
		`),

		Example: hd.Doc(`
			Validate VSA from file:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml --vsa ./vsa.json
			
			Validate VSA from Rekor:
			  ec validate vsa --image quay.io/acme/app@sha256:... --policy .ec/policy.yaml
		`),

		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()
			if trace.IsEnabled() {
				var task *trace.Task
				ctx, task = trace.NewTask(ctx, "ec:validate-vsa-prepare")
				defer task.End()
				cmd.SetContext(ctx)
			}

			// For now, create a simple policy for testing
			// TODO: Implement full policy setup
			data.policy = nil

			return
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if trace.IsEnabled() {
				var task *trace.Task
				ctx, task = trace.NewTask(ctx, "ec:validate-vsa")
				defer task.End()
				cmd.SetContext(ctx)
			}

			// Create the appropriate retriever based on whether vsaPath is provided
			var retriever vsa.VSADataRetriever
			if data.vsaPath != "" {
				// Use file-based retriever
				fs := utils.FS(ctx)
				retriever = vsa.NewFileVSADataRetriever(fs, data.vsaPath)
			} else {
				// Use Rekor-based retriever
				// Extract digest from image reference for Rekor lookup
				ref, err := name.ParseReference(data.imageRef)
				if err != nil {
					return fmt.Errorf("invalid image reference: %w", err)
				}
				digest := ref.Identifier()

				rekorRetriever, err := vsa.NewRekorVSADataRetriever(vsa.DefaultRetrievalOptions(), digest)
				if err != nil {
					return fmt.Errorf("failed to create Rekor retriever: %w", err)
				}
				retriever = rekorRetriever
			}

			// Call the validation function
			result, err := validate(ctx, data.imageRef, data.policy, retriever, data.publicKey)
			if err != nil {
				return err
			}

			// Output the result
			if len(data.output) > 0 {
				for _, outputFormat := range data.output {
					switch outputFormat {
					case "json":
						jsonData, err := json.MarshalIndent(result, "", "  ")
						if err != nil {
							return fmt.Errorf("failed to marshal result to JSON: %w", err)
						}
						fmt.Println(string(jsonData))
					case "yaml":
						// Simple YAML-like output for now
						fmt.Printf("Passed: %t\n", result.Passed)
						fmt.Printf("Signature Verified: %t\n", result.SignatureVerified)
						fmt.Printf("Summary: %s\n", result.Summary)
						fmt.Printf("Image Digest: %s\n", result.ImageDigest)
						fmt.Printf("Passing Count: %d\n", result.PassingCount)
						fmt.Printf("Total Required: %d\n", result.TotalRequired)

						if len(result.MissingRules) > 0 {
							fmt.Printf("Missing Rules: %d\n", len(result.MissingRules))
							for _, rule := range result.MissingRules {
								fmt.Printf("  - %s (%s): %s\n", rule.RuleID, rule.Package, rule.Reason)
							}
						}

						if len(result.FailingRules) > 0 {
							fmt.Printf("Failing Rules: %d\n", len(result.FailingRules))
							for _, rule := range result.FailingRules {
								fmt.Printf("  - %s (%s): %s - %s\n", rule.RuleID, rule.Package, rule.Message, rule.Reason)
							}
						}
					default:
						return fmt.Errorf("unsupported output format: %s", outputFormat)
					}
				}
			}

			if data.strict && !result.Passed {
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	// Add flags with required validation
	cmd.Flags().StringVarP(&data.imageRef, "image", "i", "", "OCI image reference")
	cmd.MarkFlagRequired("image") // Cobra will handle required validation

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", "", "Policy configuration")
	cmd.MarkFlagRequired("policy") // Cobra will handle required validation

	cmd.Flags().StringVarP(&data.vsaPath, "vsa", "", "", "Path to VSA file (optional - if omitted, retrieves from Rekor)")
	cmd.Flags().StringVarP(&data.publicKey, "public-key", "", "", "Public key for VSA signature verification")
	cmd.Flags().StringSliceVarP(&data.output, "output", "o", []string{"yaml"}, "Output format (json, yaml)")
	cmd.Flags().StringVarP(&data.outputFile, "output-file", "", "", "Output file path")
	cmd.Flags().BoolVarP(&data.strict, "strict", "", data.strict, "Return non-zero exit code on validation failure")
	cmd.Flags().BoolVarP(&data.noColor, "no-color", "", false, "Disable color output")
	cmd.Flags().BoolVarP(&data.forceColor, "force-color", "", false, "Force color output")

	return cmd
}
