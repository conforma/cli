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

package stub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/conforma/cli/acceptance/git"
	"github.com/conforma/cli/acceptance/kubernetes/types"
	"github.com/conforma/cli/acceptance/registry"
	"github.com/conforma/cli/acceptance/wiremock"
)

type stubCluster struct{}

// stubApiserverRunning starts the stub apiserver using WireMock
func Start(ctx context.Context) (context.Context, types.Cluster, error) {
	ctx, err := wiremock.StartWiremock(ctx)

	return ctx, stubCluster{}, err
}

func (s stubCluster) CreateNamespace(ctx context.Context) (context.Context, error) {
	// no-op, we can record or stub any namespace API calls if/when needed
	return ctx, nil
}

func expandSpecification(ctx context.Context, specification string) (string, error) {
	vars := make(map[string]string)
	if registry.IsRunning(ctx) {
		digests, err := registry.AllDigests(ctx)
		if err != nil {
			return "", err
		}

		for repositoryAndTag, digest := range digests {
			vars[fmt.Sprintf("REGISTRY_%s_DIGEST", repositoryAndTag)] = digest
		}
	}

	return os.Expand(specification, func(key string) string {
		// Handle predefined keys
		switch key {
		case "GITHOST":
			return git.Host(ctx)
		case "REGISTRY":
			uri, err := registry.Url(ctx)
			if err != nil {
				panic(err)
			}
			return uri
		}

		// Use a regular expression to match and extract dynamic keys
		re := regexp.MustCompile(`^REGISTRY_(.+)_DIGEST$`)
		matches := re.FindStringSubmatch(key)
		if len(matches) == 2 {
			if value, ok := vars[key]; ok {
				return value
			}
		}
		return ""
	}), nil
}

// CreateNamedPolicy stubs a response from the apiserver to fetch a EnterpriseContractPolicy
// custom resource from the `acceptance` namespace with the given name and specification
// the specification part can be templated using ${...} notation and supports
// `GITHOST` and `REGISTRY` variable substitution
func (s stubCluster) CreateNamedPolicy(ctx context.Context, name string, specification string) error {
	ns := "acceptance" // TODO: namespace support

	specification, err := expandSpecification(ctx, specification)
	if err != nil {
		return err
	}

	return wiremock.StubFor(ctx, wiremock.Get(wiremock.URLPathEqualTo(fmt.Sprintf("/apis/appstudio.redhat.com/v1alpha1/namespaces/%s/enterprisecontractpolicies/%s", ns, name))).
		WillReturnResponse(wiremock.NewResponse().WithBody(fmt.Sprintf(`{
				"apiVersion": "appstudio.redhat.com/v1alpha1",
				"kind": "EnterpriseContractPolicy",
				"metadata": {
				  "name": "%s",
				  "namespace": "%s"
				},
				"spec": %s
			  }`, name, ns, specification)).WithHeaders(map[string]string{"Content-Type": "application/json"}).WithStatus(200)))
}

// CreateNamedSnapshot stubs a response from the apiserver to fetch a Snapshot
// custom resource from the `acceptance` namespace with the given name and specification
func (s stubCluster) CreateNamedSnapshot(ctx context.Context, name string, specification string) error {
	ns := "acceptance"
	return wiremock.StubFor(ctx, wiremock.Get(wiremock.URLPathEqualTo(fmt.Sprintf("/apis/appstudio.redhat.com/v1alpha1/namespaces/%s/snapshots/%s", ns, name))).
		WillReturnResponse(wiremock.NewResponse().WithBody(fmt.Sprintf(`{
				"apiVersion": "appstudio.redhat.com/v1alpha1",
				"kind": "Snapshot",
				"metadata": {
				  "name": "%s",
				  "namespace": "%s"
				},
				"spec": %s
			  }`, name, ns, os.Expand(specification, func(key string) string {
			if key == "REGISTRY" {
				if registryUrl, err := registry.StubRegistry(ctx); err != nil {
					panic("No stub registry state, did you run the stub?")
				} else {
					return registryUrl
				}
			}

			return ""
		}))).WithHeaders(map[string]string{"Content-Type": "application/json"}).WithStatus(200)))
}

func (s stubCluster) CreateConfigMap(_ context.Context, _, _, _ string) error {
	return errors.New("ConfigMap creation is not supported when using the stub Kubernetes")
}

func (s stubCluster) CreateNamedNamespace(_ context.Context, _ string) error {
	return errors.New("Named namespace creation is not supported when using the stub Kubernetes")
}

func (s stubCluster) CreatePolicy(_ context.Context, _ string) error {
	return errors.New("use `Given policy configuration named \"<name>\" with specification` when using the stub Kubernetes")
}

func (s stubCluster) RunTask(_ context.Context, _, _, _ string, _ map[string]string) error {
	return errors.New("can't run tasks when using the stub Kubernetes")
}

func (s stubCluster) AwaitUntilTaskIsDone(context.Context) (bool, error) {
	return false, errors.New("can't run tasks when using the stub Kubernetes")
}

func (s stubCluster) TaskInfo(context.Context) (*types.TaskInfo, error) {
	return nil, errors.New("can't run tasks when using the stub Kubernetes")
}

// KubeConfig returns a valid kubeconfig configuration file in YAML format that
// points to the stubbed apiserver and uses no authentication
func (s stubCluster) KubeConfig(ctx context.Context) (string, error) {
	endpoint, err := wiremock.Endpoint(ctx)
	if err != nil {
		return "", err
	}

	server := strings.Replace(endpoint, "localhost", "apiserver.localhost", 1)

	if err != nil {
		return "", err
	}

	cluster := "my-cluster"

	context := "my-context"

	kubeconfig := api.Config{
		CurrentContext: context,
		Clusters: map[string]*api.Cluster{
			cluster: {
				Server: server,
			},
		},
		Contexts: map[string]*api.Context{
			context: {
				Cluster: cluster,
			},
		},
	}

	b, err := clientcmd.Write(kubeconfig)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (s stubCluster) Up(ctx context.Context) bool {
	return wiremock.IsRunning(ctx)
}

func (s stubCluster) Stop(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (s stubCluster) Registry(ctx context.Context) (string, error) {
	return registry.Url(ctx)
}

func (s stubCluster) BuildSnapshotArtifact(ctx context.Context, content string) (context.Context, error) {
	return ctx, nil
}
