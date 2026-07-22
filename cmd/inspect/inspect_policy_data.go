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

// Define the `ec inspect policy-data` command
package inspect

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	hd "github.com/MakeNowJust/heredoc/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

func inspectPolicyDataCmd() *cobra.Command {
	var (
		sourceUrls   []string
		destDir      string
		outputFormat string
	)

	validFormats := []string{"json", "yaml"}
	knownExtensions := []string{".json", ".yaml", ".yml"}

	cmd := &cobra.Command{
		Use:   "policy-data --source <source-url>",
		Short: "Read policy data from source urls and displays the data",

		Long: hd.Doc(`
			Read policy data from source urls and displays the data.

			This fetches policy sources similar to the 'ec fetch policy' command, but once
			the policy is fetched it reads json and yaml files inside the policy source and
			displays the data.

			Note that this command is not typically required to evaluate policies.
			It has been made available for troubleshooting and debugging purposes.
		`),

		Example: hd.Doc(`
			Print data from a given source url:

			ec inspect policy-data --source git::https://github.com/conforma/policy//example/data
		`),

		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains(validFormats, outputFormat) {
				return fmt.Errorf("invalid value for --output '%s'. accepted values: %s", outputFormat, strings.Join(validFormats, ", "))
			}

			ctx := cmd.Context()
			afs := utils.FS(ctx)

			if destDir == "" {
				workDir, err := utils.CreateWorkDir(afs)
				if err != nil {
					log.Debug("Failed to create work dir!")
					return err
				}
				destDir = workDir

				defer utils.CleanupWorkDir(afs, workDir)
			}

			allData := make(map[string]interface{})
			for _, url := range sourceUrls {
				s := &source.PolicyUrl{Url: url, Kind: source.PolicyKind}

				// Download
				policyDir, err := s.GetPolicy(ctx, destDir, false)
				if err != nil {
					return err
				}

				err = afero.Walk(afs, policyDir, func(path string, d fs.FileInfo, readErr error) error {
					if readErr != nil {
						return readErr
					}

					if d.IsDir() {
						return nil
					}

					fileExt := strings.ToLower(filepath.Ext(path))
					if slices.Contains(knownExtensions, fileExt) {
						log.Debugf("Found data file %s", path)

						contents, err := afero.ReadFile(afs, path)
						if err != nil {
							return nil
						}

						fileData := make(map[string]interface{})

						// Should work for both yaml and json
						err = yaml.Unmarshal(contents, &fileData)
						if err != nil {
							return err
						}

						// Merge the top level keys into a single map
						for k, v := range fileData {
							// Conftest will report a merge error if the same top level
							// key is seen twice, so let's do the same
							if _, exists := allData[k]; exists {
								return fmt.Errorf("Merge error. The '%s' key was found more than once!", k)
							}
							allData[k] = v
						}
					}

					return nil
				})
				if err != nil {
					return err
				}
			}

			out := cmd.OutOrStdout()
			if outputFormat == "yaml" {
				// Output yaml
				yamlOutput, err := yaml.Marshal(allData)
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(yamlOutput))
				return nil

			} else {
				// Default to json
				return json.NewEncoder(out).Encode(allData)
			}
		},
	}

	cmd.Flags().StringArrayVarP(&sourceUrls, "source", "s", []string{}, "policy data source url. multiple values are allowed")
	cmd.Flags().StringVarP(&destDir, "dest", "d", "", "use the specified destination directory to download the policy. if not set, a temporary directory will be used")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "json", fmt.Sprintf("output format. one of: %s", strings.Join(validFormats, ", ")))

	if err := cmd.MarkFlagRequired("source"); err != nil {
		panic(err)
	}

	return cmd
}
