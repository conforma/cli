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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// Determine policyConfig
func GetPolicyConfig(ctx context.Context, policyConfiguration string) (string, error) {
	// If the input starts with a JSON object, treat it as a JSON string
	if len(policyConfiguration) > 0 && policyConfiguration[0] == '{' {
		log.Debugf("Treating input as JSON string (length: %d)", len(policyConfiguration))
		return policyConfiguration, nil
	}

	// If policyConfiguration is not detected as a file and is detected as a git URL,
	// or if policyConfiguration is an https URL try to download a config file from
	// the provided source. If successful we read its contents and return it.
	if source.SourceIsGit(policyConfiguration) && !source.SourceIsFile(policyConfiguration) || source.SourceIsHttp(policyConfiguration) {
		log.Debugf("Fetching policy config from url: %s", policyConfiguration)

		// Create a temporary dir to download the config. This is separate from the workDir usd
		// later for downloading policy sources, but it doesn't matter because this dir is not
		// used again once the config file has been read.
		fs := utils.FS(ctx)
		tmpDir, err := utils.CreateWorkDir(fs)
		if err != nil {
			return "", err
		}
		defer utils.CleanupWorkDir(fs, tmpDir)

		// Git download and find a suitable config file
		configFile, err := source.GoGetterDownload(ctx, tmpDir, policyConfiguration)
		if err != nil {
			return "", err
		}
		log.Debugf("Loading %s as policy configuration", configFile)
		return ReadFile(ctx, configFile)
	} else if source.SourceIsFile(policyConfiguration) && utils.HasJsonOrYamlExt(policyConfiguration) {
		// If policyConfiguration is detected as a file and it has a json or yaml extension,
		// we read its contents and return it.
		log.Debugf("Loading %s as policy configuration", policyConfiguration)
		return ReadFile(ctx, policyConfiguration)
	}

	// If policyConfiguration is not a file path, git url, or https url,
	// we assume it's a string and return it as is.
	return policyConfiguration, nil
}

// Read file from the workspace and return its contents.
func ReadFile(ctx context.Context, fileName string) (string, error) {
	fs := utils.FS(ctx)
	fileBytes, err := afero.ReadFile(fs, fileName)
	if err != nil {
		return "", err
	}
	// Check for empty file as that would cause a false "success"
	if len(fileBytes) == 0 {
		err := fmt.Errorf("file %s is empty", fileName)
		return "", err
	}
	log.Debugf("Loaded %s", fileName)
	return string(fileBytes), nil
}
