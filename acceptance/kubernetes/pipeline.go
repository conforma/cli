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

package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cucumber/godog"

	"github.com/conforma/cli/acceptance/testenv"
)

func runPipeline(ctx context.Context, version, name string, params *godog.Table) error {
	c := testenv.FetchState[ClusterState](ctx)
	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}
	values := map[string]string{}
	for _, row := range params.Rows {
		values[row.Cells[0].Value] = row.Cells[1].Value
	}
	return c.cluster.RunPipeline(ctx, version, name, values)
}

func pipelineShouldComplete(ctx context.Context, outcome string) error {
	c := testenv.FetchState[ClusterState](ctx)
	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}
	info, err := c.cluster.AwaitUntilPipelineIsDone(ctx)
	if err != nil {
		return err
	}
	if info.Successful != (outcome == "succeed") {
		return fmt.Errorf("PipelineRun %s should %s, got %s", info.Name, outcome, info.Status)
	}
	return nil
}

func pipelineReportShouldHaveResult(ctx context.Context, expected string) error {
	c := testenv.FetchState[ClusterState](ctx)
	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}
	info, err := c.cluster.AwaitUntilPipelineIsDone(ctx)
	if err != nil {
		return err
	}
	raw, ok := info.Results["TEST_OUTPUT"].(string)
	if !ok {
		return fmt.Errorf("PipelineRun %s has no string TEST_OUTPUT result: %s", info.Name, info.Status)
	}
	var report struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return fmt.Errorf("invalid pipeline TEST_OUTPUT %q: %w", raw, err)
	}
	if report.Result != expected {
		return fmt.Errorf("pipeline TEST_OUTPUT result: want %q, got %s", expected, raw)
	}
	return nil
}

func addPipelineStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^version ([\d.]+) of the pipeline named "([^"]*)" is run with parameters:$`, runPipeline)
	sc.Step(`^the pipeline should (succeed|fail)$`, pipelineShouldComplete)
	sc.Step(`^the pipeline TEST_OUTPUT should report "([^"]*)"$`, pipelineReportShouldHaveResult)
}
