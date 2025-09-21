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

	hd "github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"

	validate_utils "github.com/conforma/cli/internal/validate"
)

type policyValidationFunc func(context.Context, string) error

func ValidatePolicyCmd(validate policyValidationFunc) *cobra.Command {
	data := struct {
		policyConfiguration string
		output              []string
		strict              bool
	}{
		strict: true,
	}
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate the provided EnterpriseContractPolicy spec",
		Long: hd.Doc(`
			Validate the provided EnterpriseContractPolicy spec against the EnterpriseContractPolicy spec schema used in this version of the ec CLI
		`),
		Example: hd.Doc(`
			Validate a local policy configuration file:
			ec validate policy --policy-configuration policy.yaml

			Validate a policy configuration file from a github repository:
			ec validate policy --policy-configuration github.com/org/repo/policy.yaml
`),
		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()

			policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
			if err != nil {
				allErrors = errors.Join(allErrors, err)
				return
			}
			data.policyConfiguration = policyConfiguration

			return
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Policy conforms to the schema.
			ctx := cmd.Context()
			err := validate(ctx, data.policyConfiguration)
			if err != nil {
				return fmt.Errorf("policy configuration does not conform to the EnterpriseContractPolicy spec")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Policy configuration conforms to the EnterpriseContractPolicy spec")
			return nil
		},
	}

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
	Policy configuration as:
	* file (policy.yaml)
	* git reference (github.com/user/repo//default?ref=main), or
	* inline JSON ('{sources: {...}}')")`))

	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}

	return cmd
}
