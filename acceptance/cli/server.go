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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cucumber/godog"

	log "github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/snaps"
)

type serverStateKey int

const (
	serverKey serverStateKey = iota
)

type serverState struct {
	cmd    *exec.Cmd
	port   int
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	vars   map[string]string
}

type httpResponse struct {
	statusCode int
	body       string
	header     http.Header
}

type responseKey int

const (
	httpResponseKey responseKey = iota
)

func ecServerStartedWith(ctx context.Context, parameters string) (context.Context, error) {
	ec := path.Join("dist", fmt.Sprintf("ec_%s_%s", runtime.GOOS, runtime.GOARCH))
	if _, err := os.Stat(ec); err != nil {
		return ctx, fmt.Errorf("%s does not exist, run a build (`make build`) first", ec)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ctx, fmt.Errorf("allocating free port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ctx, environment, vars, err := variables(ctx)
	if err != nil {
		return ctx, err
	}

	vars["SERVER_PORT"] = fmt.Sprintf("%d", port)

	args := os.Expand(parameters, func(key string) string {
		return vars[key]
	})

	cmd := exec.Command(ec)
	cmd.Args = append([]string{ec}, strings.Split(args, " ")...)
	cmd.Args = append(cmd.Args, "--server-port", fmt.Sprintf("%d", port))
	cmd.Env = environment

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return ctx, fmt.Errorf("starting server: %w", err)
	}

	state := &serverState{
		cmd:    cmd,
		port:   port,
		stdout: &stdout,
		stderr: &stderr,
		vars:   vars,
	}
	ctx = context.WithValue(ctx, serverKey, state)

	if err := waitForReady(port, 60*time.Second); err != nil {
		state.stop()
		return ctx, fmt.Errorf("server did not become ready: %w\nstderr: %s", err, stderr.String())
	}

	return ctx, nil
}

func waitForReady(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/ready", port)
	client := &http.Client{Timeout: 2 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s waiting for /ready on port %d", timeout, port)
}

func (s *serverState) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}

	_ = s.cmd.Process.Signal(syscall.SIGINT)

	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
}

func getServerState(ctx context.Context) (*serverState, error) {
	state, ok := ctx.Value(serverKey).(*serverState)
	if !ok {
		return nil, errors.New("no server running, use 'ec server is started with' first")
	}
	return state, nil
}

func doRequest(ctx context.Context, method, urlPath, contentType string, body io.Reader) (context.Context, error) {
	state, err := getServerState(ctx)
	if err != nil {
		return ctx, err
	}

	url := fmt.Sprintf("http://127.0.0.1:%d%s", state.port, urlPath)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return ctx, fmt.Errorf("%s %s: %w", method, urlPath, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ctx, fmt.Errorf("%s %s: %w", method, urlPath, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ctx, fmt.Errorf("reading response: %w", err)
	}

	return context.WithValue(ctx, httpResponseKey, &httpResponse{
		statusCode: resp.StatusCode,
		body:       string(respBody),
		header:     resp.Header,
	}), nil
}

func expandBody(ctx context.Context, content *godog.DocString) (string, error) {
	state, err := getServerState(ctx)
	if err != nil {
		return "", err
	}
	return os.Expand(content.Content, func(key string) string {
		return state.vars[key]
	}), nil
}

func aGETRequestIsSentToTheServer(ctx context.Context, urlPath string) (context.Context, error) {
	return doRequest(ctx, http.MethodGet, urlPath, "", nil)
}

func aPOSTRequestIsSentToTheServerWithBody(ctx context.Context, urlPath string, content *godog.DocString) (context.Context, error) {
	body, err := expandBody(ctx, content)
	if err != nil {
		return ctx, err
	}
	return doRequest(ctx, http.MethodPost, urlPath, "application/json", strings.NewReader(body))
}

func aPOSTRequestIsSentToTheServerWithContentTypeAndBody(ctx context.Context, urlPath, contentType string, content *godog.DocString) (context.Context, error) {
	body, err := expandBody(ctx, content)
	if err != nil {
		return ctx, err
	}
	return doRequest(ctx, http.MethodPost, urlPath, contentType, strings.NewReader(body))
}

func aPOSTRequestIsSentToTheServerWithFile(ctx context.Context, urlPath, filePath string) (context.Context, error) {
	state, err := getServerState(ctx)
	if err != nil {
		return ctx, err
	}

	expanded := os.Expand(filePath, func(key string) string {
		return state.vars[key]
	})

	data, err := os.ReadFile(expanded)
	if err != nil {
		return ctx, fmt.Errorf("reading file %s: %w", expanded, err)
	}

	return doRequest(ctx, http.MethodPost, urlPath, "application/yaml", strings.NewReader(string(data)))
}

func getResponse(ctx context.Context) (*httpResponse, error) {
	resp, ok := ctx.Value(httpResponseKey).(*httpResponse)
	if !ok {
		return nil, errors.New("no HTTP response, send a request first")
	}
	return resp, nil
}

func theResponseStatusShouldBe(ctx context.Context, expected int) error {
	resp, err := getResponse(ctx)
	if err != nil {
		return err
	}

	if resp.statusCode != expected {
		return fmt.Errorf("expected status %d, got %d\nbody: %s", expected, resp.statusCode, resp.body)
	}
	return nil
}

func theResponseShouldContain(ctx context.Context, expected string) error {
	resp, err := getResponse(ctx)
	if err != nil {
		return err
	}

	if !strings.Contains(resp.body, expected) {
		return fmt.Errorf("expected response to contain %q\nbody: %s", expected, resp.body)
	}
	return nil
}

func theResponseShouldMatchTheSnapshot(ctx context.Context) error {
	resp, err := getResponse(ctx)
	if err != nil {
		return err
	}

	state, err := getServerState(ctx)
	if err != nil {
		return err
	}

	return snaps.MatchSnapshot(ctx, "response", resp.body, state.vars)
}

func theResponseFieldShouldBe(ctx context.Context, field, expected string) error {
	resp, err := getResponse(ctx)
	if err != nil {
		return err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(resp.body), &data); err != nil {
		return fmt.Errorf("response is not valid JSON: %w\nbody: %s", err, resp.body)
	}

	actual := fmt.Sprintf("%v", data[field])
	if actual != expected {
		return fmt.Errorf("expected %s=%q, got %q\nbody: %s", field, expected, actual, resp.body)
	}
	return nil
}

func theResponseHeaderShouldBe(ctx context.Context, header, expected string) error {
	resp, err := getResponse(ctx)
	if err != nil {
		return err
	}

	actual := resp.header.Get(header)
	if actual != expected {
		return fmt.Errorf("expected header %s=%q, got %q", header, expected, actual)
	}
	return nil
}

// AddServerStepsTo registers server mode step definitions
func AddServerStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^ec server is started with "(.+)"$`, ecServerStartedWith)
	sc.Step(`^a GET request is sent to the server at "(.+)"$`, aGETRequestIsSentToTheServer)
	sc.Step(`^a POST request is sent to the server at "(.+)" with body$`, aPOSTRequestIsSentToTheServerWithBody)
	sc.Step(`^a POST request is sent to the server at "(.+)" with content type "(.+)" and body$`, aPOSTRequestIsSentToTheServerWithContentTypeAndBody)
	sc.Step(`^a POST request is sent to the server at "(.+)" with file "(.+)"$`, aPOSTRequestIsSentToTheServerWithFile)
	sc.Step(`^the response status should be (\d+)$`, theResponseStatusShouldBe)
	sc.Step(`^the response should contain "(.+)"$`, theResponseShouldContain)
	sc.Step(`^the response should match the snapshot$`, theResponseShouldMatchTheSnapshot)
	sc.Step(`^the response field "(.+)" should be "(.+)"$`, theResponseFieldShouldBe)
	sc.Step(`^the response header "(.+)" should be "(.+)"$`, theResponseHeaderShouldBe)

	sc.After(func(ctx context.Context, sc *godog.Scenario, scenarioErr error) (context.Context, error) {
		state, ok := ctx.Value(serverKey).(*serverState)
		if !ok {
			return ctx, nil
		}

		if scenarioErr != nil {
			var logger log.Logger
			logger, ctx = log.LoggerFor(ctx)
			logger.Log(fmt.Errorf("server stderr: %s", state.stderr.String()))
		}

		state.stop()
		return ctx, nil
	})
}
