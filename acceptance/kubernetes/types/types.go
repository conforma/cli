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

package types

import (
	"context"
)

type Cluster interface {
	Up(context.Context) bool
	Stop(context.Context) (context.Context, error)
	KubeConfig(context.Context) (string, error)
	CreateNamespace(context.Context) (context.Context, error)
	CreateNamedPolicy(context.Context, string, string) error
	CreatePolicy(context.Context, string) error
	RunTask(context.Context, string, string, string, map[string]string) error
	AwaitUntilTaskIsDone(context.Context) (bool, error)
	TaskInfo(context.Context) (*TaskInfo, error)
	CreateNamedSnapshot(context.Context, string, string) error
	CreateNamedNamespace(context.Context, string) error
	CreateConfigMap(context.Context, string, string, string) error
	Registry(context.Context) (string, error)
	BuildSnapshotArtifact(context.Context, string) (context.Context, error)
}

type TaskInfo struct {
	Name      string
	Namespace string
	Params    map[string]any
	Results   map[string]any
	Status    string
	Steps     []Step
}

type Step struct {
	Name    string
	Status  string
	Logs    string
	EnvVars map[string]string
}
