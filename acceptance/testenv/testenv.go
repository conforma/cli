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

// Package testenv contains test environment utilities
package testenv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"testing"

	"github.com/testcontainers/testcontainers-go"
)

type testEnv int

// Keys we use to look up the state in the Context
const (
	PersistStubEnvironment testEnv = iota // key to a bool flag telling if the environment is persisted
	RestoreStubEnvironment                // key to a bool flag telling if the environment is restored
	NoColors                              // key to a bool flag telling if the colors should be used in output
	VerboseOutput                         // key to a bool flag telling if verbose output (stdout/stderr) should be shown on failure
	TestingT                              // key to the *testing.T instance in Context
	persistedEnv                          // key to a map of persisted environment states
	RekorImpl                             // key to a implementation of the Rekor interface, used to prevent import cycles
	Scenario                              // key to a the *godog.Scenario of the current scenario, used to prevent import cycles
	TestUtil                              // key to a test utility struct

	persistedFile = ".persisted"
)

var (
	loader    = os.ReadFile
	persister = os.WriteFile
)

var (
	ecVersion    = "undefined"
	ecVersionErr error
	// Add a flag to track if version has been initialized
	versionInitialized bool
)

// Persist persists the environment stored in context in a ".persisted" file as JSON
func Persist(ctx context.Context) (bool, error) {
	if !Persisted(ctx) {
		return false, nil
	}

	values, ok := ctx.Value(persistedEnv).(*map[string]any)
	if !ok {
		return true, errors.New("did not find expected map type in Context for the persistedEnv value")
	}

	b, err := json.Marshal(values)
	if err != nil {
		return true, fmt.Errorf("unable to store JSON data in .persisted file: %v", err.Error())
	}

	err = persister(persistedFile, b, 0644)
	if err != nil {
		return true, fmt.Errorf("unable to write to %s file: %v", persistedFile, err.Error())
	}

	return true, nil
}

// Persisted returns true if the test environment persists after the test has finished
func Persisted(ctx context.Context) bool {
	persist, ok := ctx.Value(PersistStubEnvironment).(bool)

	// if we're either not persisting or we ran in restored environment, this is
	// to allow the environment to persist and not require both -persist and -restore
	// to be specified, i.e. when running with -restore, -persist is assumed
	return ok && persist || Restored(ctx)
}

// Restored returns true if the test environment is restored from the last persisted environment
func Restored(ctx context.Context) bool {
	restore, ok := ctx.Value(RestoreStubEnvironment).(bool)

	return ok && restore
}

// RestoreValue returns the value associated with the given key from the last preserved environment
func restoreInto(key string, val any) error {
	b, err := loader(persistedFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	var j map[string]json.RawMessage

	if err = json.Unmarshal(b, &j); err != nil {
		return err
	}

	if err = json.Unmarshal(j[key], &val); err != nil {
		return err
	}

	return nil
}

// WithState marks a struct that holds some state under a specific key
type WithState interface {
	Key() any
}

type Initializing interface {
	Initialize()
}

// persistedKey constructs a key in the form of type.value
func persistedKey[S WithState](state S) string {
	key := state.Key()

	return fmt.Sprintf("%T.%v", key, key)
}

// SetupState initializes the given state S and stores it in Context under S.Key(), if invoked
// twice for the same S.Key() the state will be set to the existing value from Context. If the
// test environment is being restored, values from the persisted file will be loaded.
func SetupState[S WithState](ctx context.Context, state **S) (context.Context, error) {
	p := ctx.Value(persistedEnv)

	if p == nil {
		p = &map[string]any{}
	}

	// we need to new() to be able to invoke S.Key()
	newS := new(S)
	key := persistedKey(*newS)

	store := *p.(*map[string]any)

	existing := store[key]

	if existing == nil {
		*state = newS
		if i, ok := any(*state).(Initializing); ok {
			i.Initialize()
		}
	} else {
		*state = existing.(*S)
	}

	store[key] = *state

	if Restored(ctx) {
		if err := restoreInto(key, &state); err != nil {
			return ctx, err
		}
	}

	return context.WithValue(ctx, persistedEnv, p), nil
}

// FetchState fetches the state from the Context stored under S.Key()
func FetchState[S WithState](ctx context.Context) *S {
	p := ctx.Value(persistedEnv)
	if p == nil {
		panic("need to invoke SetupState at least once")
	}

	newS := *new(S)
	key := persistedKey(newS)

	store := *p.(*map[string]any)

	state := store[key]
	if state == nil {
		panic(fmt.Sprintf("no state found for key %s, make sure to invoke SetupState for %T first", key, newS))
	}

	return state.(*S)
}

// HasState returns true if the state for the provided type is present in the context
func HasState[S WithState](ctx context.Context) bool {
	p := ctx.Value(persistedEnv)
	if p == nil {
		return false
	}

	newS := *new(S)
	key := persistedKey(newS)

	store := *p.(*map[string]any)

	state := store[key]
	return state != nil
}

// NoColorOutput returns true if the output produced should not contain colors, which is
// useful when a terminal or medium can't interpret ANSI colors
func NoColorOutput(ctx context.Context) bool {
	noColors, ok := ctx.Value(NoColors).(bool)

	return ok && noColors
}

func Testing(ctx context.Context) *testing.T {
	return ctx.Value(TestingT).(*testing.T)
}

func TempDir(ctx context.Context) (context.Context, string) {
	utl := &testUtil{}

	var err error
	ctx, err = SetupState[testUtil](ctx, &utl)
	if err != nil {
		panic(err)
	}

	if utl.tempDir == "" {
		t := Testing(ctx)
		utl.tempDir = t.TempDir()
	}

	return ctx, utl.tempDir
}

// TestContainersRequest modifies the req to keep the container running after the test if PersistStubEnvironment is set to true in the ctx
func TestContainersRequest(ctx context.Context, req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	persisted := Persisted(ctx)

	req.AutoRemove = !persisted
	if persisted {
		os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}

	return req
}

// CLIVersion returns the version of the CLI, useful for matching in snapshots
func CLIVersion(ctx context.Context) (string, error) {
	// For individual test runs, we need to ensure the version is always fresh
	// Check if we're in a test context and if the version needs to be refreshed
	if !versionInitialized || ecVersion == "undefined" {
		ec := path.Join("dist", fmt.Sprintf("ec_%s_%s", runtime.GOOS, runtime.GOARCH))

		cmd := exec.CommandContext(ctx, ec, "version", "--json")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		if ecVersionErr = cmd.Run(); ecVersionErr != nil {
			return ecVersion, ecVersionErr
		}

		ver := struct {
			Version string
		}{}
		if err := json.Unmarshal(stdout.Bytes(), &ver); err != nil {
			panic(err)
		}

		ecVersion = ver.Version
		versionInitialized = true
	}

	return ecVersion, ecVersionErr
}

type testUtil struct {
	tempDir string
}

func (testUtil) Key() any {
	return TestUtil
}
