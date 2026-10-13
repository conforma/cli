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

// Define the `ec inspect ecp` command
package inspect

import (
	"fmt"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	validate_utils "github.com/conforma/cli/internal/validate"
)

func inspectECPCmd() *cobra.Command {
	var (
		policyConfiguration string
		policyOverlays      []string
	)

	cmd := &cobra.Command{
		Use:   "ecp --policy <policy>",
		Short: "Inspect and display the effective EnterpriseContractPolicy configuration",

		Long: hd.Doc(`
			Load a base EnterpriseContractPolicy configuration and optionally merge it with
			overlay files, then display the resulting effective configuration.

			This is useful for debugging and understanding how policy overlays are merged
			with the base policy. The output shows the final configuration that would be
			used during validation.
		`),

		Example: hd.Doc(`
			Display a single policy configuration:

			  ec inspect ecp --policy policy.yaml

			Display the merged result of a base policy and overlays:

			  ec inspect ecp --policy standard.yaml --policy-overlay team.yaml

			Display the result of multiple overlays (applied in order):

			  ec inspect ecp --policy standard.yaml \
			    --policy-overlay team.yaml \
			    --policy-overlay hotfix.yaml
		`),

		Args: cobra.NoArgs,

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Load base policy configuration
			policyConfig, err := validate_utils.GetPolicyConfig(ctx, policyConfiguration)
			if err != nil {
				return fmt.Errorf("failed to load policy: %w", err)
			}

			// Merge overlays if provided
			if len(policyOverlays) > 0 {
				var overlays []string
				for _, overlayFile := range policyOverlays {
					overlay, err := validate_utils.GetPolicyConfig(ctx, overlayFile)
					if err != nil {
						return fmt.Errorf("failed to load policy overlay %s: %w", overlayFile, err)
					}
					overlays = append(overlays, overlay)
				}

				mergedConfig, err := validate_utils.MergePolicyConfigs(ctx, policyConfig, overlays)
				if err != nil {
					return fmt.Errorf("failed to merge policy configs: %w", err)
				}
				policyConfig = mergedConfig
			}

			// Output the effective configuration
			fmt.Println(policyConfig)
			return nil
		},
	}

	cmd.Flags().StringVarP(&policyConfiguration, "policy", "p", policyConfiguration, hd.Doc(`
		Policy configuration as:
		  * Kubernetes reference ([<namespace>/]<name>)
		  * file (policy.yaml)
		  * git reference (github.com/user/repo//default?ref=main), or
		  * inline JSON ('{sources: {...}, identity: {...}}')`))

	cmd.Flags().StringSliceVar(&policyOverlays, "policy-overlay", policyOverlays, hd.Doc(`
		Policy overlay files to merge with the base policy. Can be specified multiple times.
		Overlays are applied in order. Maps are deeply merged, arrays are concatenated.
		Supports the same formats as --policy (files, git references, inline JSON/YAML).`))

	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}

	return cmd
}
