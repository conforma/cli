// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package snaps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cucumber/godog"
	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/conforma/cli/acceptance/testenv"
)

var (
	timestampRegex      = regexp.MustCompile(`\d\d[1-9]\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})?`) // generalized timestamp in not in 200x year
	effectiveTimeRegex  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}?Z`)                                        // generalized timestamp for any year
	logTimestampRegex   = regexp.MustCompile(`^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}`)                                        // timestamp as it apears in the logs
	tempPathRegex       = regexp.MustCompile(`\$\{TEMP\}([^: \\"]+)[: ]?`)                                                    // starts with "${TEMP}" and ends with something not in path, perhaps breaks on Windows due to the colon
	randomBitsRegex     = regexp.MustCompile(`([a-f0-9]+)$`)                                                                  // in general, we add random bits to paths as suffixes
	runtimeDataDirRegex = regexp.MustCompile(`/var/workdir/data-source-[A-Za-z0-9]{6}`)                                       // mktemp directory for runtime policy data
	unixTimestamp       = regexp.MustCompile(`("| )(?:\d{10})(\\"|"|$)`)                                                      // Recent Unix timestamp in second resolution
	tektonTimestamp     = regexp.MustCompile(`\b\d{10}\.\d+\b`)                                                               // timestamp used in Tekton logs
)

type errCapture struct {
	t         *testing.T
	scenario  *godog.Scenario
	qualifier string
	err       error
}

func (e errCapture) Helper() {
	e.t.Helper()
}

func (e errCapture) Skip(args ...interface{}) {
	e.t.Skip(args...)
}

func (e errCapture) Skipf(format string, args ...interface{}) {
	e.t.Skipf(format, args...)
}

func (e errCapture) SkipNow() {
	e.t.SkipNow()
}

func (e errCapture) Name() string {
	return "TestFeatures/" + e.scenario.Name + ":" + e.qualifier
}

func (e *errCapture) Error(args ...interface{}) {
	err := errors.New(fmt.Sprint(args...))
	e.err = errors.Join(e.err, err)
}

func (e errCapture) Log(args ...interface{}) {
}

func (e errCapture) Cleanup(f func()) {
	e.t.Cleanup(f)
}

func capture(ctx context.Context, qualifier string) errCapture {
	t := testenv.Testing(ctx)

	scenario := ctx.Value(testenv.Scenario).(*godog.Scenario)
	return errCapture{
		t:         t,
		scenario:  scenario,
		qualifier: qualifier,
	}
}

func MatchSnapshot(ctx context.Context, qualifier, text string, vars map[string]string) error {
	errs := capture(ctx, qualifier)

	// snaps normalizes, but again reports this as a diff
	text = strings.ReplaceAll(text, "\r", "\\r")

	for k, v := range vars {
		text = strings.ReplaceAll(text, v, "${"+k+"}")
		// in case the value was quoted, so doubly-escaped
		text = strings.ReplaceAll(text, strconv.Quote(v), `"${`+k+`}"`)
	}

	// replace any remaining timestamps
	text = timestampRegex.ReplaceAllString(text, "$${TIMESTAMP}")

	// replace any log timestamps
	text = logTimestampRegex.ReplaceAllString(text, "$${TIMESTAMP}")

	// replace any effective time timestamps
	text = effectiveTimeRegex.ReplaceAllString(text, "$${TIMESTAMP}")

	// more timestamps, Unix here
	text = unixTimestamp.ReplaceAllString(text, "$1$${TIMESTAMP}$2")

	// Tekton timestamps
	text = tektonTimestamp.ReplaceAllString(text, "$${TIMESTAMP}")

	// handle temp directories, replace local temp path with "${TEMP}"
	text = strings.ReplaceAll(text, os.TempDir(), "${TEMP}")

	// find all ${TEMP}/dir1/dir2/.../file.ext paths
	submatches := tempPathRegex.FindAllStringSubmatch(text, -1)
	for _, submatch := range submatches {
		if len(submatch) == 1 {
			continue
		}

		path := submatch[1]

		parts := strings.Split(path, string(os.PathSeparator))

		for i, part := range parts {
			parts[i] = randomBitsRegex.ReplaceAllString(part, "$${RANDOM}")
		}

		// here we want `/` so that snapshots don't differentiate between
		// systems
		text = strings.ReplaceAll(text, path, strings.Join(parts, "/"))
	}

	// The data source directory is shared across Tekton steps and is not under /tmp.
	text = runtimeDataDirRegex.ReplaceAllString(text, "/var/workdir/data-source-$${RANDOM}")

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	scenario := ctx.Value(testenv.Scenario).(*godog.Scenario)
	snapshot := strings.TrimSuffix(filepath.Base(scenario.Uri), filepath.Ext(scenario.Uri))

	formatText := true
	var textOutput json.RawMessage
	if err := json.Unmarshal([]byte(text), &textOutput); err != nil {
		formatText = false
	}

	if formatText {
		formattedText, err := json.MarshalIndent(textOutput, "", "  ")
		if err != nil {
			return err
		}
		text = string(formattedText)
	}

	snaps.WithConfig(snaps.Dir(path.Join(wd, "features", "__snapshots__")), snaps.Filename(snapshot)).MatchSnapshot(&errs, text)

	return errs.err
}
