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

// Package cli runs the ec command line and asserts the expected outcome.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/cucumber/godog"
	c "github.com/doiit/picocolors"
	"github.com/pkg/diff"
	"github.com/yudai/gojsondiff"
	"github.com/yudai/gojsondiff/formatter"

	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/git"
	"github.com/conforma/cli/acceptance/image"
	"github.com/conforma/cli/acceptance/kubernetes"
	"github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/registry"
	"github.com/conforma/cli/acceptance/rekor"
	"github.com/conforma/cli/acceptance/snaps"
	"github.com/conforma/cli/acceptance/testenv"
	"github.com/conforma/cli/acceptance/tuf"
)

type status struct {
	*exec.Cmd
	vars   map[string]string
	err    error
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

// Vars returns the variables map from the status
func (s *status) Vars() map[string]string {
	return s.vars
}

type key int

const (
	processStatusKey key = iota
	cmdEnvVar        key = iota
)

type diffy []gojsondiff.Delta

func (d diffy) Modified() bool {
	return len(d) > 0
}

func (d diffy) Deltas() []gojsondiff.Delta {
	return d
}

func variables(ctx context.Context) (context.Context, []string, map[string]string, error) {
	// environment that the ec command line will run with
	// we need to keep the $PATH, otherwise go-getter could
	// fail if it can't locate the git command
	environment := []string{
		"PATH=" + os.Getenv("PATH"),
		"COVERAGE_FILEPATH=" + os.Getenv("COVERAGE_FILEPATH"), // where to put the coverage file, $COVERAGE_FILEPATH is provided by the Makefile, if empty it'll be $TMPDIR
		"COVERAGE_FILENAME=" + os.Getenv("COVERAGE_FILENAME"), // suffix for the coverage file
		"HOME=/tmp",
	}

	// variables that can be substituted on the command line
	// provided by the `parameters`` parameter

	ctx, tmpdir := testenv.TempDir(ctx)
	vars := map[string]string{
		"TMPDIR": tmpdir,
	}

	var err error
	if environment, vars, err = setupKubernetes(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupRegistry(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupRekor(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupKeys(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupSigs(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupGitHost(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, vars, err = setupTUF(ctx, vars, environment); err != nil {
		return ctx, nil, nil, err
	}

	if environment, err = setupCmdEnvironmentVariable(ctx, environment); err != nil {
		return ctx, nil, nil, err
	}

	if vars, err = setupCliVersion(ctx, vars); err != nil {
		return ctx, nil, nil, err
	}

	return ctx, environment, vars, nil
}

// ecCommandIsRunWith launches the ec command line with provided parameters.
// If parameters contain references to variables in ${...} syntax those will
// be substituted with the values appropriate for this scenario execution
func ecCommandIsRunWith(ctx context.Context, parameters string) (context.Context, error) {
	// path to the ec* binary given specific operating system and archive as built by
	// make build
	ec := path.Join("dist", fmt.Sprintf("ec_%s_%s", runtime.GOOS, runtime.GOARCH))
	info, err := os.Stat(ec)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ctx, fmt.Errorf("%s does not exist, run a build (`make build`) first", ec)
		}

		return ctx, err
	}

	if !info.Mode().IsRegular() {
		return ctx, fmt.Errorf("%s is a not a regular file", ec)
	}

	ctx, environment, vars, err := variables(ctx)
	if err != nil {
		return ctx, err
	}

	// performs the actual substitution of ${...} with the
	// values from `vars``
	args := os.Expand(parameters, func(key string) string {
		return vars[key]
	})

	cmd := exec.Command(ec)
	// note, argument at 0 is the path to ec command line
	cmd.Args = append([]string{ec}, strings.Split(args, " ")...)
	cmd.Env = environment

	// capture stdout and stderr
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	sts := status{Cmd: cmd, vars: vars, err: err, stdout: &stdout, stderr: &stderr}

	err = cmd.Run()
	if err != nil {
		// we're not asserting here, so let's log the error
		// depending on how we assert the error might or
		// might not surface again
		var logger log.Logger
		logger, ctx = log.LoggerFor(ctx)
		logger.Log(err)
	}

	// store the outcome in the Context
	return context.WithValue(ctx, processStatusKey, &sts), nil
}

func setupKeys(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	// there could be several key pairs created, for testing
	// signature validation against a wrong public key we want
	// to avail all public keys that have been generated for
	// substitution
	publicKeys := crypto.PublicKeysFrom(ctx)
	privateKeys := crypto.PrivateKeysFrom(ctx)

	for name, publicKey := range publicKeys {
		key, err := os.CreateTemp("", "*.pub")
		if err != nil {
			return environment, vars, err
		}

		if !testenv.Persisted(ctx) {
			testenv.Testing(ctx).Cleanup(func() {
				os.Remove(key.Name())
			})
		}

		_, err = key.WriteString(publicKey)
		if err != nil {
			return environment, vars, err
		}
		err = key.Close()
		if err != nil {
			return environment, vars, err
		}

		vars[name+"_PUBLIC_KEY"] = key.Name()
		// Handle some variations in indentation
		vars[fmt.Sprintf("__________%s_PUBLIC_KEY", name)] = snaps.Indent(publicKey, 10)

		vars[name+"_PUBLIC_KEY_JSON"] = strings.ReplaceAll(publicKey, "\n", "\\n")

		publicKeyXML := bytes.Buffer{}
		if err := xml.EscapeText(&publicKeyXML, []byte(publicKey)); err != nil {
			return environment, vars, err
		}
		vars[name+"_PUBLIC_KEY_XML"] = publicKeyXML.String()
	}

	// Setup private keys for VSA functionality
	for name, privateKey := range privateKeys {
		privKey, err := os.CreateTemp("", "*.pem")
		if err != nil {
			return environment, vars, err
		}

		if !testenv.Persisted(ctx) {
			testenv.Testing(ctx).Cleanup(func() {
				os.Remove(privKey.Name())
			})
		}

		_, err = privKey.WriteString(privateKey)
		if err != nil {
			return environment, vars, err
		}
		err = privKey.Close()
		if err != nil {
			return environment, vars, err
		}

		vars[name+"_PRIVATE_KEY"] = privKey.Name()
	}

	return environment, vars, nil
}

func setupSigs(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	type valFunc func(context.Context, string) (map[string]string, error)

	setVar := func(name string, v valFunc) error {
		vals, err := v(ctx, name)
		if err != nil {
			return err
		}

		for n, v := range vals {
			vars[n] = v
		}

		return nil
	}

	for n, v := range map[string]valFunc{
		"ATTESTATION_SIGNATURE": image.AttestationSignaturesFrom,
		"IMAGE_SIGNATURE":       image.ImageSignaturesFrom,
	} {
		if err := setVar(n, v); err != nil {
			return environment, vars, err
		}
	}

	return environment, vars, nil
}

func setupRekor(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	if !rekor.IsRunning(ctx) {
		return environment, vars, nil
	}

	rekorURL, err := rekor.StubRekor(ctx)
	if err != nil {
		return environment, vars, err
	}

	vars["REKOR"] = rekorURL

	// If TUF is initialized, skip setting SIGSTORE_REKOR_PUBLIC_KEY to avoid conflicts.
	if !tuf.Initialized(ctx) {
		f, err := os.CreateTemp("", "ec-acceptance-rekor-pub-*")
		if err != nil {
			return environment, vars, err
		}
		defer f.Close()
		if _, err := f.Write(rekor.PublicKey(ctx)); err != nil {
			return environment, vars, err
		}
		environment = append(environment, fmt.Sprintf("SIGSTORE_REKOR_PUBLIC_KEY=%s", f.Name()))
	}

	return environment, vars, nil
}

func setupRegistry(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	if !registry.IsRunning(ctx) {
		return environment, vars, nil
	}

	registryURL, err := registry.StubRegistry(ctx)
	if err != nil {
		return environment, vars, err
	}

	vars["REGISTRY"] = registryURL

	digests, err := registry.AllDigests(ctx)
	if err != nil {
		return environment, vars, err
	}

	for repositoryAndTag, digest := range digests {
		vars[fmt.Sprintf("REGISTRY_%s_DIGEST", repositoryAndTag)] = digest
	}

	return environment, vars, nil
}

func setupKubernetes(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	if !testenv.HasState[kubernetes.ClusterState](ctx) {
		return environment, vars, nil
	}

	c := testenv.FetchState[kubernetes.ClusterState](ctx)

	if !c.Up(ctx) {
		return environment, vars, nil
	}

	kubeconfig, err := os.CreateTemp("", "*.kubeconfig")
	if err != nil {
		return environment, vars, err
	}

	testenv.Testing(ctx).Cleanup(func() {
		if !testenv.Persisted(ctx) {
			os.Remove(kubeconfig.Name())
		}
	})

	cfg, err := c.KubeConfig(ctx)
	if err != nil {
		return environment, vars, err
	}

	_, err = kubeconfig.WriteString(cfg)
	if err != nil {
		return environment, vars, err
	}
	err = kubeconfig.Close()
	if err != nil {
		return environment, vars, err
	}

	environment = append(environment, "KUBECONFIG="+kubeconfig.Name())

	return environment, vars, nil
}

func setupGitHost(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	if !git.IsRunning(ctx) {
		return environment, vars, nil
	}

	environment = append(environment,
		fmt.Sprintf("SSL_CERT_FILE=%s", git.CertificatePath(ctx)),
		"GIT_SSL_NO_VERIFY=true",
		// Add git configuration to handle intermittent connection issues
		"GIT_HTTP_LOW_SPEED_LIMIT=1000",
		"GIT_HTTP_LOW_SPEED_TIME=30",
		"GIT_HTTP_TIMEOUT=60",
	)

	vars["GITHOST"] = git.Host(ctx)
	latestCommit := git.LatestCommit(ctx)
	if latestCommit != "" {
		vars["LATEST_COMMIT"] = latestCommit
	}
	return environment, vars, nil
}

func setupTUF(ctx context.Context, vars map[string]string, environment []string) ([]string, map[string]string, error) {
	if !tuf.IsRunning(ctx) {
		// Don't write sigstore TUF cache. Tests run concurently and there could be race issues
		// against the filesystem.
		environment = append(environment, "SIGSTORE_NO_CACHE=1")
		return environment, vars, nil
	}

	tufURL, err := tuf.Stub(ctx)
	if err != nil {
		return environment, vars, err
	}
	vars["TUF"] = tufURL

	vars["CERT_IDENTITY"] = "https://kubernetes.io/namespaces/default/serviceaccounts/default"
	vars["CERT_ISSUER"] = "https://kubernetes.default.svc.cluster.local"

	environment = append(environment, fmt.Sprintf("TUF_ROOT=%s", tuf.Root(ctx)))

	return environment, vars, nil
}

// theExitStatusIs checks that the exit status of ec command line is 0
// (success), and logs profusely in case of it being != 0
func theExitStatusIs(ctx context.Context, expected int) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	// if the error is an exec.ExitError we need to assert the status to
	// be expected below and not fail here
	var exitErr *exec.ExitError
	if status.err != nil && !errors.As(status.err, &exitErr) {
		return fmt.Errorf("failed to invoke the ec command: %#v", status.err)
	}

	if status.Cmd.ProcessState.ExitCode() != expected {
		return fmt.Errorf("ec exited with %d", status.ProcessState.ExitCode())
	}

	return nil
}

// theStandardOutputShouldContain looks at the standard output (stdout) of the last invoked ec
// command and compares the expected output with the resulted output. Special handling is done
// for JSON output, it is compared disregarding key order in objects, and values can contain
// regular expressions to match the expected to resulted output even when dealing with dynamic
// values such as port numbers or temporary paths
func theStandardOutputShouldContain(ctx context.Context, expected *godog.DocString) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	if expected == nil {
		return errors.New("must provide expected output")
	}

	expectedStdOut := os.Expand(expected.Content, func(key string) string {
		return status.vars[key]
	})

	stdout := status.stdout.String()

	// shortcut, if the output is exactly as expected
	if stdout == expectedStdOut {
		return nil
	}

	if matched, err := regexp.MatchString(expectedStdOut, stdout); matched && err == nil {
		return nil
	}

	// see if the expected value is JSON, i.e. if it starts with either { or [
	expectedTrimmed := strings.TrimLeftFunc(expectedStdOut, unicode.IsSpace)
	expectdIsJSONMap := expectedTrimmed[0] == '{'
	expectdIsJSONArray := expectedTrimmed[0] == '['
	stdoutTrimmed := strings.TrimLeftFunc(stdout, unicode.IsSpace)
	stdoutIsJSON := len(stdoutTrimmed) > 0 && (stdoutTrimmed[0] == '{' || stdoutTrimmed[0] == '[')
	if (expectdIsJSONMap || expectdIsJSONArray) && stdoutIsJSON {
		expectedBytes := []byte(expectedStdOut)

		diff, err := compareJSON(expectedBytes, status.stdout.Bytes(), expectdIsJSONArray)
		if err != nil {
			return err
		}

		if !diff.Modified() {
			// expected and resulting JSON is the same
			return nil
		}

		// we need to unmarshal the expected (left) JSON for output formatting
		// and to check for any regular expressions in the expected JSON's values
		var left any
		err = json.Unmarshal(expectedBytes, &left)
		if err != nil {
			return err
		}

		diff = filterMatchedByRegexp(left, diff)

		if !diff.Modified() {
			// there was a difference, but the values matched regular expression
			// given in the expected JSON
			return nil
		}

		f := formatter.NewAsciiFormatter(left, formatter.AsciiFormatterConfig{
			ShowArrayIndex: true,
			Coloring:       !testenv.NoColorOutput(ctx),
		})
		formattedDiff, err := f.Format(diff)
		if err != nil {
			return err
		}

		return fmt.Errorf("expected and actual output differ:\n%s", formattedDiff)
	}

	var b bytes.Buffer
	err = diff.Text("stdout", "expected", status.stdout, expectedStdOut, &b)
	if err != nil {
		return err
	}

	return fmt.Errorf("expected and actual output differ:\n%s", b.String())
}

// theStandardErrorShouldContain looks at the standard error (stderr) of the last invoked ec
// command and compares the expected error with the resulted error.
func theStandardErrorShouldContain(ctx context.Context, expected *godog.DocString) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	if expected == nil {
		return errors.New("must provide expected error")
	}

	expectedStdErr := os.Expand(expected.Content, func(key string) string {
		return status.vars[key]
	})

	stderr := status.stderr.String()

	// shortcut, if the output is exactly as expected
	if stderr == expectedStdErr {
		return nil
	}

	if matched, err := regexp.MatchString(expectedStdErr, stderr); matched && err == nil {
		return nil
	}

	return fmt.Errorf("expected error:\n%s\nnot found in standard error:\n%s", expected, stderr)
}

// theStandardOutputShouldMatchBaseline reads the expected text from a file instead of directly
// from the feature file
func theStandardOutputShouldMatchBaseline(ctx context.Context, fileName string) error {
	b, err := os.ReadFile(path.Join("acceptance", fileName))
	if err != nil {
		return err
	}

	docString := godog.DocString{Content: string(b)}
	return theStandardOutputShouldContain(ctx, &docString)
}

func filterMatchedByRegexp(obj any, diff gojsondiff.Diff) diffy {
	deltas := diff.Deltas()
	if v, ok := obj.(map[string]any); ok {
		filterObjectMatchedByRegexp(v, &deltas)
	} else if v, ok := obj.([]any); ok {
		filterArrayMatchedByRegexp(v, &deltas)
	}

	filterOutEmptyDeltas(&deltas)

	return deltas
}

func filterOutEmptyDeltas(deltas *[]gojsondiff.Delta) {
	filtered := make([]gojsondiff.Delta, 0, len(*deltas))
	for _, delta := range *deltas {
		switch delta := delta.(type) {
		case *gojsondiff.Object:
			filterOutEmptyDeltas(&delta.Deltas)

			if len(delta.Deltas) > 0 {
				filtered = append(filtered, delta)
			}
		case *gojsondiff.Array:
			filterOutEmptyDeltas(&delta.Deltas)

			if len(delta.Deltas) > 0 {
				filtered = append(filtered, delta)
			}
		default:
			filtered = append(filtered, delta)
		}
	}

	*deltas = filtered
}

func filterArrayMatchedByRegexp(ary []any, deltas *[]gojsondiff.Delta) {
	removeIdxs := make([]int, 0, len(*deltas))
	for i, v := range ary {
		pos := gojsondiff.Index(i)
		if idx := filterDeltaRegexp(v, pos, deltas); idx != nil {
			removeIdxs = append(removeIdxs, *idx)
		}
	}

	sort.Ints(removeIdxs)
	for i, removed := range removeIdxs {
		idx := removed - i
		*deltas = append((*deltas)[:idx], (*deltas)[idx+1:]...)
	}
}

func filterObjectMatchedByRegexp(obj map[string]any, deltas *[]gojsondiff.Delta) {
	removeIdxs := make([]int, 0, len(*deltas))
	for k, v := range obj {
		pos := gojsondiff.Name(k)
		if idx := filterDeltaRegexp(v, pos, deltas); idx != nil {
			removeIdxs = append(removeIdxs, *idx)
		}
	}

	sort.Ints(removeIdxs)
	for i, removed := range removeIdxs {
		idx := removed - i
		*deltas = append((*deltas)[:idx], (*deltas)[idx+1:]...)
	}
}

func filterDeltaRegexp(value any, pos gojsondiff.Position, deltas *[]gojsondiff.Delta) *int {
	for i, delta := range *deltas {
		if delta, ok := delta.(gojsondiff.PostDelta); !ok || delta.PostPosition() != pos {
			continue
		}

		matched := false
		switch delta := delta.(type) {
		case *gojsondiff.Object:
			filterObjectMatchedByRegexp(value.(map[string]any), &delta.Deltas)
		case *gojsondiff.Array:
			filterArrayMatchedByRegexp(value.([]any), &delta.Deltas)
		case *gojsondiff.Modified:
			matched = matchesRegex(delta.OldValue, delta.NewValue)
		case *gojsondiff.TextDiff:
			matched = matchesRegex(delta.OldValue, delta.NewValue)
		}

		if matched {
			return &i
		}
	}

	return nil
}

func matchesRegex(regex any, value any) bool {
	var r *regexp.Regexp
	var v string
	var err error

	switch regex := regex.(type) {
	case string:
		r, err = regexp.Compile(regex)
	case fmt.Stringer:
		r, err = regexp.Compile(regex.String())
	default:
		r, err = regexp.Compile(fmt.Sprintf("%v", r))
	}

	switch value := value.(type) {
	case string:
		v = value
	case fmt.Stringer:
		v = value.String()
	default:
		v = fmt.Sprintf("%v", value)
	}

	return err == nil && r.MatchString(v)
}

func ecStatusFrom(ctx context.Context) (*status, error) {
	status, ok := ctx.Value(processStatusKey).(*status)
	if !ok {
		return nil, errors.New("can't find ec process state, did you invoke ec beforehand")
	}

	return status, nil
}

// EcStatusFrom returns the command execution status from the context
// This is an exported wrapper for ecStatusFrom to allow access from other packages
func EcStatusFrom(ctx context.Context) (*status, error) {
	return ecStatusFrom(ctx)
}

// logExecution logs the details of the execution and offers hits as how to
// troubleshoot test failures by using persistent environment
func logExecution(ctx context.Context) {
	noColors := testenv.NoColorOutput(ctx)
	if c.SUPPORT_COLOR != !noColors {
		c.SUPPORT_COLOR = !noColors
	}

	s, err := ecStatusFrom(ctx)
	if err != nil {
		return // the ec wasn't invoked no status was stored
	}

	output := &strings.Builder{}
	outputSegment := func(name string, v any) {
		output.WriteString("\n\n")
		output.WriteString(c.Underline(c.Bold(name)))
		output.WriteString(fmt.Sprintf("\n%v", v))
	}

	outputSegment("Command", s.Cmd)
	outputSegment("State", fmt.Sprintf("Exit code: %d\nPid: %d", s.ProcessState.ExitCode(), s.ProcessState.Pid()))
	outputSegment("Environment", strings.Join(s.Env, "\n"))
	var varsStr []string
	for k, v := range s.vars {
		varsStr = append(varsStr, fmt.Sprintf("%s=%s", k, v))
	}
	outputSegment("Variables", strings.Join(varsStr, "\n"))
	if s.stdout.Len() == 0 {
		outputSegment("Stdout", c.Italic("* No standard output"))
	} else {
		outputSegment("Stdout", c.Green(s.stdout.String()))
	}
	if s.stderr.Len() == 0 {
		outputSegment("Stdout", c.Italic("* No standard error"))
	} else {
		outputSegment("Stderr", c.Red(s.stderr.String()))
	}

	if testenv.Persisted(ctx) {
		var environment []string
		for _, e := range s.Env {
			if strings.HasPrefix(e, "KUBECONFIG=") || strings.HasPrefix(e, "SIGSTORE_") {
				environment = append(environment, e)
			}
		}

		output.WriteString("\n" + c.Bold("NOTE") + ": " + fmt.Sprintf("The test environment is persisted, to recreate the failure run:\n%s %s\n\n", strings.Join(environment, " "), strings.Join(s.Cmd.Args, " ")))
	} else {
		output.WriteString("\n" + c.Bold("HINT") + ": To recreate the failure re-run the test with `-args -persist` to persist the stubbed environment\n\n")
	}

	fmt.Print(output.String())
}

func matchSnapshot(ctx context.Context) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	stdout := snaps.MatchSnapshot(ctx, "stdout", status.stdout.String(), status.vars)
	stderr := snaps.MatchSnapshot(ctx, "stderr", status.stderr.String(), status.vars)

	if stdout == nil && stderr == nil {
		return nil
	}

	return errors.Join(stdout, stderr)
}

func matchFileSnapshot(ctx context.Context, file string) error {
	status, err := ecStatusFrom(ctx)
	if err != nil {
		return err
	}

	expanded := os.Expand(file, func(key string) string {
		return status.vars[key]
	})

	content, err := os.ReadFile(expanded)
	if err != nil {
		return err
	}

	return snaps.MatchSnapshot(ctx, file, string(content), status.vars)
}

func createGenericFile(ctx context.Context, name string, content *godog.DocString) (context.Context, error) {
	ctx, _, vars, err := variables(ctx)
	if err != nil {
		return ctx, err
	}

	expand := func(text string) string {
		return os.Expand(text, func(key string) string {
			return vars[key]
		})
	}

	file := expand(name)

	data := expand(content.Content)

	return ctx, os.WriteFile(file, []byte(data), 0o600)
}

func createTrackBundleFile(ctx context.Context, name string, content *godog.DocString) (context.Context, error) {
	return createGenericFile(ctx, name, content)
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^ec command is run with "(.+)"$`, ecCommandIsRunWith)
	sc.Step(`^the exit status should be (\d+)$`, theExitStatusIs)
	sc.Step(`^the standard output should contain$`, theStandardOutputShouldContain)
	sc.Step(`^the standard output should match baseline file "(.+)"$`, theStandardOutputShouldMatchBaseline)
	sc.Step(`^the standard error should contain$`, theStandardErrorShouldContain)
	sc.Step(`^the environment variable is set "([^"]*)"$`, theEnvironmentVarilableIsSet)
	sc.Step(`^the output should match the snapshot$`, matchSnapshot)
	sc.Step(`^the "([^"]*)" file should match the snapshot$`, matchFileSnapshot)
	sc.Step(`^a file named "([^"]*)" containing$`, createGenericFile)
	sc.Step(`^a track bundle file named "([^"]*)" containing$`, createTrackBundleFile)
	sc.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		logExecution(ctx)

		return ctx, nil
	})
}

// gojsondiff handles arrays and maps different
// gojsondiff.Compare unmarshals to map[string]interface{}
func compareJSON(left []byte, right []byte, isArray bool) (gojsondiff.Diff, error) {
	differ := gojsondiff.New()
	var err error
	var diff gojsondiff.Diff
	if isArray {
		var leftObj, rightObj []interface{}
		err = json.Unmarshal(left, &leftObj)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(right, &rightObj)
		if err != nil {
			return nil, err
		}
		diff = differ.CompareArrays(leftObj, rightObj)
	} else {
		diff, err = differ.Compare(left, right)
		if err != nil {
			return nil, err
		}
	}
	return diff, nil
}

// theEnvironmentVarilableIsSet sets the given environment variable to be used
// when launching a command.
func theEnvironmentVarilableIsSet(ctx context.Context, parameter string) (context.Context, error) {
	environment, ok := ctx.Value(cmdEnvVar).([]string)
	if !ok {
		return ctx, errors.New("unexpected type for environment in context during initialization")
	}
	environment = append(environment, parameter)

	ctx = context.WithValue(ctx, cmdEnvVar, environment)
	return ctx, nil
}

// setupCmdEnvironmentVariable adds to the given environment slice any other
// environment values from the context.
func setupCmdEnvironmentVariable(ctx context.Context, environment []string) ([]string, error) {
	newEnvironment, ok := ctx.Value(cmdEnvVar).([]string)
	if !ok && environment != nil {
		return environment, nil
	}
	environment = append(environment, newEnvironment...)
	return environment, nil
}

func setupCliVersion(ctx context.Context, vars map[string]string) (map[string]string, error) {
	v, err := testenv.CLIVersion(ctx)
	if err != nil {
		return vars, err
	}
	vars["EC_VERSION"] = v

	return vars, nil
}
