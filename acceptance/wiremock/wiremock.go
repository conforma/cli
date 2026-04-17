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

// Package wiremock does HTTP protocol stubbing using WireMock (https://wiremock.org/)
package wiremock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"

	"cuelang.org/go/pkg/strings"
	"github.com/cucumber/godog"
	"github.com/otiai10/copy"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/wiremock/go-wiremock"

	"github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/testenv"
)

type key int

const (
	wireMockStateKey key = iota                                 // The state of the wiremock persisted between runs and in Context
	wireMockImage        = "docker.io/wiremock/wiremock:2.33.2" // container image used to run WireMock
)

// to make it simpler on imports in the clients of this package,
// we re-expose functions from the wiremock package, add others
// as needed

var (
	Get              = wiremock.Get
	Post             = wiremock.Post
	URLPathEqualTo   = wiremock.URLPathEqualTo
	MatchingJsonPath = wiremock.MatchingJsonPath
	NewResponse      = wiremock.NewResponse
)

type client struct {
	*wiremock.Client

	unmatchedURL string
}

// newClient creates a new WireMock client, delegating to the wiremock.Client
// with additional methods we require not present there
func newClient(url string) *client {
	w := *wiremock.NewClient(url)

	return &client{unmatchedURL: fmt.Sprintf("%s/__admin/requests/unmatched", url), Client: &w}
}

// The result of /__admin/requests/unmatched endpoint
type unmatchedRequest struct {
	URL                 string `json:"url"`
	AbsoluteURL         string `json:"absoluteUrl"`
	Method              string
	Headers             map[string]interface{}
	Body                string
	BrowserProxyRequest bool
	LoggedDate          int64
	LoggedDateString    string
}

type wiremockState struct {
	URL       string
	Container testcontainers.Container `json:"-"`
}

func (g wiremockState) Key() any {
	return wireMockStateKey
}

func (g wiremockState) Up() bool {
	return g.URL != ""
}

// contentTypeFromString returns the content-type part of a MIME media type
// for example given "type/subtype;parameter=value;..." returns "type/subtype"
func contentTypeFromString(s string) string {
	for _, part := range strings.Split(s, ",") {
		contentType, _, err := mime.ParseMediaType(part)
		if err != nil {
			continue
		}

		// first that parses without error
		return contentType
	}

	return "unknown/unknown"
}

// contentTypeFrom returns the content-type based on the "Accept" HTTP
// header of a HTTP request, given that HTTP headers can be multivalued
// it either returns the single value or the first value of many
// "&lt;unknown&gt;" is returned when the "Accept" HTTP header is not
// present, or it contains no values
func contentTypeFrom(u unmatchedRequest) string {
	for key, value := range u.Headers {
		if strings.ToLower(key) == "accept" {
			switch v := value.(type) {
			case string:
				return contentTypeFromString(v)
			case []interface{}:
				if len(v) >= 1 {
					return contentTypeFromString(fmt.Sprintf("%s", v[0]))
				}
			}
		}
	}

	return "<unknown>"
}

// String formats the unmatched request and generates a snippet to help
// stub the request, useful when reporting unmatched requests i.e. those
// that have been received but no stubbing was defined
func (u unmatchedRequest) String() string {
	str := fmt.Sprintf("Found unmatched %s request to %s\n", u.Method, u.URL)

	if u.Body != "" {
		str += "The request contained this HTTP body:\n" + u.Body
	}

	str += fmt.Sprintf(`Stub it by adding:
wiremock.StubFor(ctx, wiremock.%s(wiremock.URLPathEqualTo("%s")).
	WillReturnResponse(wiremock.NewResponse().WithBody("<body>").WithHeaders(
		map[string]string{"Content-Type": "%s"},
	).WithStatus(200)
	))`, strings.ToTitle(strings.ToLower(u.Method)), u.URL, contentTypeFrom(u))

	return str
}

// UnmatchedRequests queries the WireMock admin API for any unmatched requests
// i.e. those that have been received but no stubbing was defined and returns
// them
func (c *client) UnmatchedRequests() ([]unmatchedRequest, error) {
	res, err := http.Get(c.unmatchedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unmatched requests via `%s`: %s", c.unmatchedURL, err.Error())
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unmatched requests via `%s`: failed to read the response, error: %s", c.unmatchedURL, err.Error())
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch unmatched requests via `%s`: bad response status: %d, response: %s", c.unmatchedURL, res.StatusCode, string(bodyBytes))
	}

	var unmatchedRequestsResponse struct {
		Requests []unmatchedRequest `json:"requests"`
	}

	err = json.Unmarshal(bodyBytes, &unmatchedRequestsResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unmatched requests via `%s`: unable to unmarshal JSON error: %s, given JSON: `%s`", c.unmatchedURL, err.Error(), string(bodyBytes))
	}

	return unmatchedRequestsResponse.Requests, nil
}

// StartWiremock starts the WireMock instance if one is not already running
func StartWiremock(ctx context.Context) (context.Context, error) {
	var state *wiremockState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		// we already stored the key in this Context, a WireMock instance
		// must be running already
		return ctx, nil
	}

	recordings, err := recordingsDir()
	if err != nil {
		return ctx, err
	}

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        wireMockImage,
		ExposedPorts: []string{"0.0.0.0::8080/tcp", "0.0.0.0::8443/tcp"},
		WaitingFor:   wait.ForHTTP("/__admin/mappings").WithPort("8080/tcp"),
		Binds:        []string{fmt.Sprintf("%s:/recordings:z", recordings)},
		Cmd: []string{
			"--root-dir=/recordings",
			"--verbose",
		},
	})

	logger, ctx := log.LoggerFor(ctx)
	w, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           logger,
	})
	if err != nil {
		return ctx, fmt.Errorf("unable to run GenericContainer: %v", err)
	}

	state.Container = w

	port, err := w.MappedPort(ctx, "8080/tcp")
	if err != nil {
		return ctx, err
	}

	url := fmt.Sprintf("http://localhost:%d", port.Int())
	state.URL = url

	return ctx, nil
}

// wiremockFrom returns the client used to interact with the WireMock admin API
func wiremockFrom(ctx context.Context) (*client, error) {
	state := testenv.FetchState[wiremockState](ctx)

	if !state.Up() {
		return nil, errors.New("wireMock is not up, did you start it first")
	}

	return newClient(state.URL), nil
}

// StubFor delegates to the wiremock.StubFor of the WireMock instance assigned
// to the provided Context
func StubFor(ctx context.Context, stubRule *wiremock.StubRule) error {
	w, err := wiremockFrom(ctx)
	if err != nil {
		return err
	}

	return w.StubFor(stubRule)
}

// Endpoint returns the URL of the WireMock instance
func Endpoint(ctx context.Context) (string, error) {
	state := testenv.FetchState[wiremockState](ctx)

	if !state.Up() {
		return "", errors.New("wireMock is not up, did you start it first")
	}

	return state.URL, nil
}

func IsRunning(ctx context.Context) bool {
	if !testenv.HasState[wiremockState](ctx) {
		return false
	}

	state := testenv.FetchState[wiremockState](ctx)

	return state.Up()
}

// AddStepsTo makes sure that any unmatched requests, i.e. requests that are not
// stubbed get reported at the end of a scenario run, and terminates the container
// after the scenario completes
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.After(func(ctx context.Context, finished *godog.Scenario, scenarioErr error) (context.Context, error) {
		if IsRunning(ctx) {
			if w, err := wiremockFrom(ctx); err == nil {
				if unmatched, err := w.UnmatchedRequests(); err == nil && len(unmatched) > 0 {
					logger, _ := log.LoggerFor(ctx)
					logger.Log("Found unmatched WireMock requests:")
					for i, u := range unmatched {
						logger.Logf("[%d]: %s", i, u)
					}
				}
			}
		}

		if testenv.Persisted(ctx) {
			return ctx, nil
		}

		if !testenv.HasState[wiremockState](ctx) {
			return ctx, nil
		}

		state := testenv.FetchState[wiremockState](ctx)
		if state.Container != nil {
			if err := state.Container.Terminate(ctx); err != nil {
				logger, _ := log.LoggerFor(ctx)
				logger.Warnf("failed to terminate wiremock container: %v", err)
			}
		}

		return ctx, nil
	})
}

func recordingsDir() (string, error) {
	// cwd is the directory where the test is run from i.e. $GITROOT
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	aggregate, err := os.MkdirTemp("", "ec-acceptance-wiremock.*")
	if err != nil {
		return "", err
	}

	sourcePath := path.Join(cwd, "acceptance", "wiremock", "recordings")
	services, err := os.ReadDir(sourcePath)
	if err != nil {
		return "", err
	}

	for _, s := range services {
		if !s.IsDir() {
			continue
		}
		src := path.Join(sourcePath, s.Name())
		if err := copy.Copy(src, aggregate); err != nil {
			return "", err
		}
	}
	return aggregate, nil
}
