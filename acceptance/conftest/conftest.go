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

package conftest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/cucumber/godog"
	c "github.com/doiit/picocolors"
	"github.com/pkg/diff"

	"github.com/conforma/cli/acceptance/registry"
	"github.com/conforma/cli/acceptance/testenv"
)

// runConftest runs Conftest via "go run" so that the version of Conftest is
// governed using tools/go.mod. The command parameter is split on the whitespace
// characters and select variables enclosed in ${...} are replaced with
// appropriate values. The produces parameter holds the path to the expected
// file and content at its content.
func runConftest(ctx context.Context, command, produces string, content *godog.DocString) error {
	var err error

	registryUrl, err := registry.Url(ctx)
	if err != nil {
		return err
	}

	// we run conftest in a temporary directory so we can independently check
	// any files created there
	dir, err := os.MkdirTemp("", "conftest")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// supported variable substitutions
	vals := map[string]string{
		"REGISTRY":           registryUrl,
		"TODAY_PLUS_30_DAYS": time.Now().Round(time.Hour*24).UTC().AddDate(0, 0, 30).Format(time.RFC3339),
		"TMPDIR":             dir,
	}

	args := os.Expand(command, func(key string) string {
		return vals[key]
	})
	if err != nil {
		return err
	}

	// setup a go project, required for `go mod run`, meh
	init := exec.Command("go", "mod", "init", "github.com/wat")
	init.Dir = dir
	if err := init.Run(); err != nil {
		return err
	}

	// determine where the root of the project is
	_, file, _, _ := runtime.Caller(0)
	root := path.Join(path.Dir(file), "../..") // root of the git repository

	// run a version of Conftest governed by the tools/go.mod file
	params := append([]string{"run", "-modfile", path.Join(root, "tools/go.mod"), "github.com/open-policy-agent/conftest"}, strings.Fields(args)...)

	cmd := exec.Command("go", params...)

	cmd.Dir = dir
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	var cmdErr error
	defer func() {
		if cmdErr == nil {
			return
		}

		noColors := testenv.NoColorOutput(ctx)
		if c.SUPPORT_COLOR != !noColors {
			c.SUPPORT_COLOR = !noColors
		}

		fmt.Printf("\n\t%s", c.Underline(c.Bold("Conftest command")))
		fmt.Printf("\n\t%s\n\n\t", cmd)
		fmt.Println(c.Underline(c.Bold("Stdout")))
		fmt.Printf("\t%s", strings.ReplaceAll(stdout.String(), "\n", "\n\t"))
		fmt.Printf("\n\t%s", c.Underline(c.Bold("Stderr")))
		fmt.Printf("\n\t%s", strings.ReplaceAll(stderr.String(), "\n", "\n\t"))
	}()

	if cmdErr = cmd.Run(); cmdErr != nil {
		return fmt.Errorf("failure running conftest: %w", cmdErr)
	}

	buff, err := os.ReadFile(path.Join(dir, produces))
	if err != nil {
		return err
	}

	expected := os.Expand(content.Content, func(key string) string {
		return vals[key]
	})
	got := string(buff)
	if expected == got {
		return nil
	}

	var b bytes.Buffer
	err = diff.Text("bundle", "expected", got, expected, &b)
	if err != nil {
		return err
	}

	return fmt.Errorf("expected file %s differs:\n%s", produces, b.String())
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^running conftest "([^"]*)" produces "([^"]*)" containing:$`, runConftest)
}
