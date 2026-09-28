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

package kind

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tektoncd/cli/pkg/formatted"
	pipeline "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	tekton "github.com/tektoncd/pipeline/pkg/client/clientset/versioned/typed/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/acceptance/kubernetes/types"
	"github.com/conforma/cli/acceptance/testenv"
)

// localPipeline loads the checked-out definition, changing only bundle locations
// to use the tasks built from this checkout by buildTaskBundleImage.
func localPipeline(version, name, bundle string) (*pipeline.Pipeline, error) {
	content, err := os.ReadFile(filepath.Join("pipelines", name, version, name+".yaml"))
	if err != nil {
		return nil, err
	}
	var definition pipeline.Pipeline
	if err := yaml.UnmarshalStrict(content, &definition); err != nil {
		return nil, err
	}
	for i := range definition.Spec.Tasks {
		task := &definition.Spec.Tasks[i]
		if task.TaskRef == nil || task.TaskRef.Resolver != "bundles" {
			return nil, fmt.Errorf("pipeline task %q must use a bundle resolver", task.Name)
		}
		found := false
		for j := range task.TaskRef.Params {
			param := &task.TaskRef.Params[j]
			if param.Name == "bundle" {
				param.Value = pipeline.ParamValue{Type: pipeline.ParamTypeString, StringVal: bundle}
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("pipeline task %q has no bundle parameter", task.Name)
		}
	}
	return &definition, nil
}

// RunPipeline runs the repository pipeline against the local task bundles.
func (k *kindCluster) RunPipeline(ctx context.Context, version, name string, params map[string]string) error {
	t := testenv.FetchState[testState](ctx)
	bundle := fmt.Sprintf("registry.image-registry.svc.cluster.local:%d/ec-task-bundle:%s", k.registryPort, version)
	definition, err := localPipeline(version, name, bundle)
	if err != nil {
		return err
	}
	tkn, err := tekton.NewForConfig(k.config)
	if err != nil {
		return err
	}
	tknParams := make([]pipeline.Param, 0, len(params))
	for n, v := range params {
		tknParams = append(tknParams, stringParam(ctx, n, v, t))
	}
	pr, err := tkn.PipelineRuns(t.namespace).Create(ctx, &pipeline.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "acceptance-pipelinerun-"},
		Spec: pipeline.PipelineRunSpec{
			PipelineSpec:    &definition.Spec,
			Params:          tknParams,
			TaskRunTemplate: pipeline.PipelineTaskRunTemplate{ServiceAccountName: "default"},
			Timeouts:        &pipeline.TimeoutFields{Pipeline: &metav1.Duration{Duration: 10 * time.Minute}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	t.pipelineRun = pr.Name
	return nil
}

// AwaitUntilPipelineIsDone polls with a deadline. A timeout or API failure is
// always an error, never an expected negative validation result.
func (k *kindCluster) AwaitUntilPipelineIsDone(ctx context.Context) (*types.PipelineInfo, error) {
	t := testenv.FetchState[testState](ctx)
	tkn, err := tekton.NewForConfig(k.config)
	if err != nil {
		return nil, err
	}
	var pr *pipeline.PipelineRun
	err = wait.PollUntilContextTimeout(ctx, time.Second, 11*time.Minute, true, func(ctx context.Context) (bool, error) {
		var err error
		pr, err = tkn.PipelineRuns(t.namespace).Get(ctx, t.pipelineRun, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pr.IsDone(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("waiting for PipelineRun %s/%s: %w", t.namespace, t.pipelineRun, err)
	}
	results := map[string]any{}
	for _, result := range pr.Status.Results {
		results[result.Name] = paramValue(result.Value)
	}
	// Preserve condition messages (including resolution/validation failures) in
	// assertion errors instead of reporting just a boolean status.
	return &types.PipelineInfo{
		Name:       pr.Name,
		Status:     fmt.Sprintf("%s: %v", formatted.Condition(pr.Status.Conditions), pr.Status.Conditions),
		Successful: pr.IsSuccessful(),
		Results:    results,
	}, nil
}
