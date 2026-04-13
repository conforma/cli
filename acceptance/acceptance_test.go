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

package acceptance

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/conforma/cli/acceptance/cli"
	"github.com/conforma/cli/acceptance/conftest"
	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/git"
	"github.com/conforma/cli/acceptance/image"
	"github.com/conforma/cli/acceptance/kubernetes"
	"github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/pipeline"
	"github.com/conforma/cli/acceptance/registry"
	"github.com/conforma/cli/acceptance/rekor"
	"github.com/conforma/cli/acceptance/tekton"
	"github.com/conforma/cli/acceptance/testenv"
	"github.com/conforma/cli/acceptance/tuf"
	"github.com/conforma/cli/acceptance/vsa"
	"github.com/conforma/cli/acceptance/wiremock"
)

// NOTE: flags need to be initialized with the package in order to be recognized
// a flag that can be set by running the test with "-args -persist" command line options
var persist = flag.Bool("persist", false, "persist the stubbed environment to facilitate debugging")

// run acceptance tests with the persisted environment
var restore = flag.Bool("restore", false, "restore last persisted environment")

var noColors = flag.Bool("no-colors", false, "disable colored output")

// specify a subset of scenarios to run filtering by given tags
var tags = flag.String("tags", "", "select scenarios to run based on tags")

// random seed to use
var seed = flag.Int64("seed", -1, "random seed to use for the tests")

// failedScenario tracks information about a failed scenario
type failedScenario struct {
	Name     string
	Location string
	Error    error
	LogFile  string
}

// scenarioTracker tracks failed scenarios across all test runs
type scenarioTracker struct {
	mu              sync.Mutex
	failedScenarios []failedScenario
}

func (st *scenarioTracker) addFailure(name, location, logFile string, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.failedScenarios = append(st.failedScenarios, failedScenario{
		Name:     name,
		Location: location,
		Error:    err,
		LogFile:  logFile,
	})
}

func (st *scenarioTracker) printSummary(t *testing.T) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if len(st.failedScenarios) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "FAILED SCENARIOS SUMMARY (%d)\n", len(st.failedScenarios))
	fmt.Fprintf(os.Stderr, "========================================\n")
	for i, fs := range st.failedScenarios {
		fmt.Fprintf(os.Stderr, "%d. %s\n", i+1, fs.Name)
		fmt.Fprintf(os.Stderr, "   Location: %s\n", fs.Location)
		if fs.Error != nil {
			fmt.Fprintf(os.Stderr, "   Error: %v\n", fs.Error)
		}
		if fs.LogFile != "" {
			fmt.Fprintf(os.Stderr, "   Log file: %s\n", fs.LogFile)
		}
		if i < len(st.failedScenarios)-1 {
			fmt.Fprintf(os.Stderr, "\n")
		}
	}
	fmt.Fprintf(os.Stderr, "========================================\n")
}

var tracker = &scenarioTracker{}

// initializeScenario adds all steps and registers all hooks to the
// provided godog.ScenarioContext
func initializeScenario(sc *godog.ScenarioContext) {
	cli.AddStepsTo(sc)
	crypto.AddStepsTo(sc)
	git.AddStepsTo(sc)
	image.AddStepsTo(sc)
	kubernetes.AddStepsTo(sc)
	registry.AddStepsTo(sc)
	rekor.AddStepsTo(sc)
	tekton.AddStepsTo(sc)
	wiremock.AddStepsTo(sc)
	pipeline.AddStepsTo(sc)
	conftest.AddStepsTo(sc)
	tuf.AddStepsTo(sc)
	vsa.AddStepsTo(sc)

	sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		logger, ctx := log.LoggerFor(ctx)
		logger.Name(sc.Name)

		return context.WithValue(ctx, testenv.Scenario, sc), nil
	})

	sc.After(func(ctx context.Context, scenario *godog.Scenario, scenarioErr error) (context.Context, error) {
		logger, ctx := log.LoggerFor(ctx)

		logFile := logger.LogFile()
		logger.Close()

		if scenarioErr != nil {
			tracker.addFailure(scenario.Name, scenario.Uri, logFile, scenarioErr)
		}

		_, err := testenv.Persist(ctx)

		if scenarioErr == nil {
			// Clean up log files for passing scenarios
			os.Remove(logFile)
		}

		return ctx, err
	})
}

func initializeSuite(ctx context.Context) func(*godog.TestSuiteContext) {
	return func(tsc *godog.TestSuiteContext) {
		kubernetes.InitializeSuite(ctx, tsc)
	}
}

// setupContext creates a Context prepopulated with the *testing.T and *persist
// values
func setupContext(t *testing.T) context.Context {
	ctx := context.WithValue(context.Background(), testenv.TestingT, t)
	ctx = context.WithValue(ctx, testenv.PersistStubEnvironment, *persist)
	ctx = context.WithValue(ctx, testenv.RestoreStubEnvironment, *restore)
	ctx = context.WithValue(ctx, testenv.NoColors, *noColors)

	return ctx
}

// TestFeatures launches all acceptance test scenarios running them
// in random order in parallel threads equal to the number of available
// cores
func TestFeatures(t *testing.T) {
	// change the directory to repository root, makes for easier paths
	if err := os.Chdir(".."); err != nil {
		t.Error(err)
	}

	featuresDir, err := filepath.Abs("features")
	if err != nil {
		t.Error(err)
	}

	ctx := setupContext(t)

	opts := godog.Options{
		Format:         "pretty",
		Paths:          []string{featuresDir},
		Randomize:      *seed,
		Concurrency:    runtime.NumCPU(),
		TestingT:       t,
		DefaultContext: ctx,
		Tags:           *tags,
		NoColors:       *noColors,
		Strict:         true,
	}

	suite := godog.TestSuite{
		ScenarioInitializer:  initializeScenario,
		TestSuiteInitializer: initializeSuite(ctx),
		Options:              &opts,
	}

	exitCode := suite.Run()

	// Print summary of failed scenarios
	tracker.printSummary(t)

	if exitCode != 0 {
		t.Fatalf("acceptance test suite failed with exit code %d", exitCode)
	}
}

func TestMain(t *testing.M) {
	v := t.Run()

	// After all tests have run `go-snaps` can check for not used snapshots
	if _, err := snaps.Clean(t); err != nil {
		fmt.Println("Error cleaning snaps:", err)
		os.Exit(1)
	}

	os.Exit(v)
}
