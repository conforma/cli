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

package tuf

import (
	"context"
	_ "embed"
	"os"
	"strings"
	"sync"

	"github.com/cucumber/godog"
	"github.com/otiai10/copy"
	"github.com/sigstore/sigstore/pkg/tuf"

	"github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/testenv"
	"github.com/conforma/cli/acceptance/wiremock"
)

type key int

const tufStateKey = key(0)

type state struct {
	rootDir     string
	initialized bool
}

func (state) Key() any {
	return tufStateKey
}

func (s state) Up() bool {
	return s.rootDir != ""
}

//go:embed root.json
var rootJSON []byte

// stubRunning starts the WireMock instance with the TUF recordings.
func stubRunning(ctx context.Context) (context.Context, error) {
	var state *state
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		return ctx, nil
	}

	rootDir, err := os.MkdirTemp("", "ec-acceptance-tuf.*")
	if err != nil {
		return ctx, err
	}
	state.rootDir = rootDir

	ctx, err = wiremock.StartWiremock(ctx)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

// initializeRoot populates the TUF_ROOT from a previously initialized origin TUF.
func initializeRoot(ctx context.Context) (context.Context, error) {
	var logger log.Logger
	logger, ctx = log.LoggerFor(ctx)

	origin, err := originRoot(ctx)
	if err != nil {
		return ctx, err
	}

	newTUFRoot := Root(ctx)
	logger.Infof("Copying TUF root from origin %q to %q", origin, newTUFRoot)
	if err := copy.Copy(origin, newTUFRoot); err != nil {
		return ctx, err
	}

	state := testenv.FetchState[state](ctx)
	state.initialized = true
	return ctx, nil
}

// Stub returns the `http://host:port` of the stubbed TUF.
// This is used for CLI context (external WireMock)
func Stub(ctx context.Context) (string, error) {
	endpoint, err := wiremock.Endpoint(ctx)
	if err != nil {
		return "", err
	}

	return strings.Replace(endpoint, "localhost", "tuf.localhost", 1), nil
}

// IsRunning returns true if the stubbed TUF is running.
func IsRunning(ctx context.Context) bool {
	return testenv.HasState[state](ctx)
}

// Root returns the location of the TUF root for the given context.
func Root(ctx context.Context) string {
	if !testenv.HasState[state](ctx) {
		return ""
	}
	state := testenv.FetchState[state](ctx)
	return state.rootDir
}

// Initialized returns true if the TUF root has been initialized.
func Initialized(ctx context.Context) bool {
	if !testenv.HasState[state](ctx) {
		return false
	}
	state := testenv.FetchState[state](ctx)
	return state.initialized
}

var (
	singletonTUFOnce = sync.Once{}
	originRootDir    string
)

// originRoot populates a TUF root once from the stubbed TUF which can be used by the tests.
func originRoot(ctx context.Context) (string, error) {
	var err error
	singletonTUFOnce.Do(func() {
		var mirror string
		mirror, err = Stub(ctx)
		if err != nil {
			return
		}

		previousTUFRoot := os.Getenv("TUF_ROOT")
		var newTUFRoot string
		newTUFRoot, err = os.MkdirTemp("", "ec-acceptance-tuf-origin.*")
		if err != nil {
			return
		}
		if err = os.Setenv("TUF_ROOT", newTUFRoot); err != nil {
			return
		}
		defer func() {
			_ = os.Setenv("TUF_ROOT", previousTUFRoot)
		}()

		if err = tuf.Initialize(ctx, mirror, rootJSON); err != nil {
			return
		}
		originRootDir = newTUFRoot
	})
	if err != nil {
		return "", err
	}
	return originRootDir, nil
}

func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub tuf running$`, stubRunning)
	sc.Step(`^a initialized tuf root$`, initializeRoot)
}
