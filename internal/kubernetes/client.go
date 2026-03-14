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
	"errors"

	ecc "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type contextKey string

const clientContextKey contextKey = "ec.kubernetes.client"

type Client interface {
	FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error)
	FetchSnapshot(ctx context.Context, ref string) (*app.Snapshot, error)
}

type kubernetesClient struct {
	client dynamic.Interface
}

var kubeconfig string

func AddKubeconfigFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to the Kubernetes config file to use")
}

func WithClient(ctx context.Context, client Client) context.Context {
	return context.WithValue(ctx, clientContextKey, client)
}

// NewClient constructs a new kubernetes with the default "live" client
func NewClient(ctx context.Context) (Client, error) {
	client, ok := ctx.Value(clientContextKey).(Client)
	if ok && client != nil {
		return client, nil
	}

	c, err := createK8SClient()
	if err != nil {
		log.Debug("Failed to create k8s client!")
		return nil, err
	}

	return &kubernetesClient{
		client: c,
	}, nil
}

func createK8SClient() (client dynamic.Interface, err error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil)

	var config *rest.Config
	config, err = clientConfig.ClientConfig()
	if err != nil {
		return
	}

	client, err = dynamic.NewForConfig(config)

	return
}

// FetchEnterpriseContractPolicy gets the Enterprise Contract Policy from the given
// reference in a Kubernetes cluster.
//
// The reference is expected to be in the format [<namespace>/]<name>. If it does not contain
// a namespace, the current namespace is used.
//
//nolint:dupl // similar structure to FetchSnapshot but different types
func (k *kubernetesClient) FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error) {
	if len(ref) == 0 {
		return nil, errors.New("policy reference cannot be empty")
	}
	log.Debugf("Raw policy reference: %q", ref)

	name, err := NamespacedName(ref)
	if err != nil {
		return nil, err
	}
	log.Debugf("Parsed policy reference: %v", name)
	if name.Namespace == "" {
		return nil, errors.New("unable to determine namespace for policy")
	}

	var unstructuredPolicy *unstructured.Unstructured
	if unstructuredPolicy, err = k.client.Resource(ecc.GroupVersion.WithResource("enterprisecontractpolicies")).Namespace(name.Namespace).Get(ctx, name.Name, v1.GetOptions{}); err != nil {
		log.Debugf("Failed to fetch the policy from cluster: %s", err)
		return nil, err
	}

	policy := ecc.EnterpriseContractPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredPolicy.UnstructuredContent(), &policy); err != nil {
		log.Debugf("Failed to convert unstructured content to concrete policy structure: %s", err)
		return nil, err
	}

	log.Debugf("Policy successfully fetched from cluster: %#v", policy)

	return &policy, nil
}

// FetchSnapshot gets the AppStudio Snapshot from the given
// reference in a Kubernetes cluster.
//
// The reference is expected to be in the format [<namespace>/]<name>. If it does not contain
// a namespace, the current namespace is used.
//
//nolint:dupl // similar structure to FetchEnterpriseContractPolicy but different types
func (k *kubernetesClient) FetchSnapshot(ctx context.Context, ref string) (*app.Snapshot, error) {
	if len(ref) == 0 {
		return nil, errors.New("snapshot reference cannot be empty")
	}
	log.Debugf("Raw snapshot reference: %q", ref)

	name, err := NamespacedName(ref)
	if err != nil {
		return nil, err
	}
	log.Debugf("Parsed snapshot reference: %v", name)
	if name.Namespace == "" {
		return nil, errors.New("unable to determine namespace for snapshot")
	}

	var unstructuredSnapshot *unstructured.Unstructured
	if unstructuredSnapshot, err = k.client.Resource(app.GroupVersion.WithResource("snapshots")).Namespace(name.Namespace).Get(ctx, name.Name, v1.GetOptions{}); err != nil {
		log.Debugf("Failed to fetch the snapshot from cluster: %s", err)
		return nil, err
	}

	snapshot := app.Snapshot{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredSnapshot.UnstructuredContent(), &snapshot); err != nil {
		log.Debugf("Failed to convert unstructured content to concrete snapshot structure: %s", err)
		return nil, err
	}

	log.Debugf("Snapshot successfully fetched from cluster: %#v", snapshot)

	return &snapshot, nil
}
