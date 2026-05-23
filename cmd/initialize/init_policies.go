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

// Define the `ec init-policies` command
package initialize

import (
	"fmt"
	"path/filepath"

	hd "github.com/MakeNowJust/heredoc/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/utils"
)

func initPoliciesCmd() *cobra.Command {
	var destDir string

	cmd := &cobra.Command{
		Use:   "policies --dest-dir <directory-url>",
		Short: "Initialize a directory with minimal EC scaffolding",

		Long: hd.Doc(`
			This command creates the necessary files for a minimal EC policy setup in the
			specified destination directory.

			More information about authoring policies is available in the Conforma documentation:
			https://conforma.dev/docs/policy/authoring.html
		`),

		Example: hd.Doc(`
			Initialize the "my-policy" directory with minimal EC policy scaffolding:

			  ec init policies --dest-dir my-policy
		`),

		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			samplePolicy := hd.Doc(`
				# Simplest never-failing policy
				package main

				# METADATA
				# title: Allow rule
				# description: This rule will never fail
				# custom:
				#   short_name: acceptor
				#   failure_msg: Always succeeds
				#   solution: Easy
				#   collections:
				#   - A
				deny contains result if {
					false
					result := "Never denies"
				}
			`)
			if destDir == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "%s", samplePolicy)
				return nil
			}
			fs := utils.FS(ctx)
			workDir := destDir
			err := fs.MkdirAll(workDir, 0755)
			if err != nil {
				log.Debug("Failed to create policy directory!")
				return err
			}
			policyPath := filepath.Join(workDir, "sample.rego")
			file, err := fs.Create(policyPath)
			if err != nil {
				log.Debug("Failed to create sample policy!")
				return err
			}
			defer file.Close()
			fmt.Fprintf(file, "%s", samplePolicy)
			return nil
		},
	}

	cmd.Flags().StringVarP(&destDir, "dest-dir", "d", "", "Directory to use when creating EC policy scaffolding. If not specified stdout will be used.")
	return cmd
}
