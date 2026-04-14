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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/tektoncd/cli/pkg/formatted"
	pipeline "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	tekton "github.com/tektoncd/pipeline/pkg/client/clientset/versioned/typed/pipeline/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/kubernetes/types"
	"github.com/conforma/cli/acceptance/kustomize"
	"github.com/conforma/cli/acceptance/testenv"
)

// createPolicyObject creates the EnterpriseContractPolicy object with the given
// Spec from the specification expected as a JSON string
func (k *kindCluster) createPolicyObject(ctx context.Context, specification string) (*ecc.EnterpriseContractPolicy, error) {
	t := testenv.FetchState[testState](ctx)

	specification = os.Expand(specification, func(key string) string {
		if strings.HasSuffix(key, "_PUBLIC_KEY") {
			publicKeys := crypto.PublicKeysFrom(ctx)
			keyName := strings.TrimSuffix(key, "_PUBLIC_KEY")
			publicKey, ok := publicKeys[keyName]
			if !ok {
				panic(fmt.Sprintf("Unexpected or no value found for public key named: `%s`", keyName))
			}

			if escaped, err := json.Marshal(publicKey); err == nil {
				return string(escaped)
			} else {
				panic(err)
			}
		}

		return ""
	})

	policySpec := ecc.EnterpriseContractPolicySpec{}
	if err := json.Unmarshal([]byte(specification), &policySpec); err != nil {
		return nil, err
	}

	return &ecc.EnterpriseContractPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: ecc.GroupVersion.String(),
			Kind:       "EnterpriseContractPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: t.namespace,
		},
		Spec: policySpec,
	}, nil
}

// createPolicy creates the EnterpriseContractPolicy custom resource in the test
// context namespace
func (k *kindCluster) createPolicy(ctx context.Context, policy *ecc.EnterpriseContractPolicy) error {
	policyMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&policy)
	if err != nil {
		return err
	}

	unstructuredPolicy := unstructured.Unstructured{}
	unstructuredPolicy.SetUnstructuredContent(policyMap)

	t := testenv.FetchState[testState](ctx)
	created, err := k.dynamic.Resource(ecc.GroupVersion.WithResource("enterprisecontractpolicies")).Namespace(t.namespace).Create(ctx, &unstructuredPolicy, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// remember the created policy in the test context
	t.policy = created.GetName()

	return nil
}

// createSnapshotObject creates the Snapshot object with the given
// Spec from the specification expected as a JSON string
func (k *kindCluster) createSnapshotObject(ctx context.Context, specification string) (*app.Snapshot, error) {
	t := testenv.FetchState[testState](ctx)

	snapshotSpec := app.SnapshotSpec{}
	if err := json.Unmarshal([]byte(specification), &snapshotSpec); err != nil {
		return nil, err
	}

	return &app.Snapshot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: app.GroupVersion.String(),
			Kind:       "Snapshot",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: t.namespace,
		},
		Spec: snapshotSpec,
	}, nil
}

// createSnapshot creates the Snapshot custom resource in the test
// context namespace
func (k *kindCluster) createSnapshot(ctx context.Context, snapshot *app.Snapshot) error {
	snapshotMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&snapshot)
	if err != nil {
		return err
	}

	unstructuredSnapshot := unstructured.Unstructured{}
	unstructuredSnapshot.SetUnstructuredContent(snapshotMap)

	t := testenv.FetchState[testState](ctx)
	created, err := k.dynamic.Resource(ecc.GroupVersion.WithResource("snapshots")).Namespace(t.namespace).Create(ctx, &unstructuredSnapshot, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// remember the created policy in the test context
	t.snapshot = created.GetName()

	return nil
}

// CreateNamedPolicy creates a EnterpriseContractPolicy custom resource with the
// given name and specification in the test context namespace
func (k *kindCluster) CreateNamedPolicy(ctx context.Context, name string, specification string) error {
	policy, err := k.createPolicyObject(ctx, specification)
	if err != nil {
		return err
	}

	policy.ObjectMeta.Name = name

	return k.createPolicy(ctx, policy)
}

// CreatePolicy creates an EnterpriseContractPolicy with a random name and the
// provided specification in the test context namespace
func (k *kindCluster) CreatePolicy(ctx context.Context, specification string) error {
	policy, err := k.createPolicyObject(ctx, specification)
	if err != nil {
		return err
	}
	policy.ObjectMeta.GenerateName = "acceptance-policy-"

	return k.createPolicy(ctx, policy)
}

// CreateNamedSnapshot creates a EnterpriseContractPolicy custom resource with the
// given name and specification in the test context namespace
func (k *kindCluster) CreateNamedSnapshot(ctx context.Context, name string, specification string) error {
	snapshot, err := k.createSnapshotObject(ctx, specification)
	if err != nil {
		return err
	}

	snapshot.ObjectMeta.Name = name

	return k.createSnapshot(ctx, snapshot)
}

// CreateConfigMap creates a ConfigMap with the given name and namespace with the provided content
// Also creates necessary RBAC permissions for cross-namespace access
func (k *kindCluster) CreateConfigMap(ctx context.Context, name, namespace, content string) error {
	var data map[string]string

	// Parse JSON content and extract individual fields as ConfigMap data keys
	if strings.HasPrefix(strings.TrimSpace(content), "{") {
		// Parse JSON content
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(content), &jsonData); err != nil {
			return fmt.Errorf("failed to parse JSON content: %w", err)
		}

		// Convert to string map for ConfigMap data
		data = make(map[string]string)
		for key, value := range jsonData {
			if value != nil {
				data[key] = fmt.Sprintf("%v", value)
			}
		}
	} else {
		// For non-JSON content, store as-is under a single key
		data = map[string]string{
			"content": content,
		}
	}

	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}

	// Create the ConfigMap (or update if it already exists)
	if _, err := k.client.CoreV1().ConfigMaps(namespace).Create(ctx, configMap, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// ConfigMap exists, so get the existing one to retrieve its ResourceVersion
			existing, err := k.client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get existing ConfigMap: %w", err)
			}
			// Set the ResourceVersion from the existing ConfigMap
			configMap.ResourceVersion = existing.ResourceVersion
			// Now update with the proper ResourceVersion
			if _, err := k.client.CoreV1().ConfigMaps(namespace).Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update existing ConfigMap: %w", err)
			}
		} else {
			return err
		}
	}

	// Create RBAC permissions for cross-namespace ConfigMap access
	// This allows any service account to read ConfigMaps from any namespace
	if err := k.ensureConfigMapRBAC(ctx); err != nil {
		return fmt.Errorf("failed to create RBAC permissions: %w", err)
	}

	return nil
}

// ensureConfigMapRBAC creates necessary RBAC permissions for ConfigMap access across namespaces
func (k *kindCluster) ensureConfigMapRBAC(ctx context.Context) error {
	// Create ClusterRole for ConfigMap reading (idempotent)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acceptance-configmap-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	if _, err := k.client.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{}); err != nil {
		// Ignore error if ClusterRole already exists
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create ClusterRole: %w", err)
		}
	}

	// Create ClusterRoleBinding for all service accounts (idempotent)
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acceptance-configmap-reader-binding",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "acceptance-configmap-reader",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:serviceaccounts",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	if _, err := k.client.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{}); err != nil {
		// Ignore error if ClusterRoleBinding already exists
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create ClusterRoleBinding: %w", err)
		}
	}

	return nil
}

// CreateNamedNamespace creates a namespace with the specified name
func (k *kindCluster) CreateNamedNamespace(ctx context.Context, name string) error {
	_, err := k.client.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, metav1.CreateOptions{})

	// Ignore error if namespace already exists
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil
	}

	return err
}

// CreateNamespace creates a randomly-named namespace for the test to execute in
// and stores it in the test context
func (k *kindCluster) CreateNamespace(ctx context.Context) (context.Context, error) {
	t := &testState{}
	ctx, err := testenv.SetupState(ctx, &t)
	if err != nil {
		return ctx, err
	}

	if t.namespace != "" {
		// already created
		return ctx, nil
	}

	namespace, err := k.client.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acceptance-",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return ctx, err
	}

	t.namespace = namespace.GetName()

	t.registry, err = k.Registry(ctx)
	if err != nil {
		return ctx, err
	}

	// to prevent concurrency issues we lock/unlock the environment mutex here
	render := func() ([]byte, error) {
		envMutex.Lock()
		if err := os.Setenv("WORK_NAMESPACE", fmt.Sprint(t.namespace)); err != nil {
			return nil, err
		}

		defer func() {
			_ = os.Unsetenv("WORK_NAMESPACE") // ignore errors
			envMutex.Unlock()
		}()

		return kustomize.Render(path.Join("work"))
	}

	yaml, err := render()
	if err != nil {
		return ctx, err
	}

	return ctx, applyResources(ctx, k, yaml)
}

// stringParam generates a Tekton Parameter optionally expanding certain variables
func stringParam(ctx context.Context, name, value string, t *testState) pipeline.Param {
	vars := map[string]string{
		"NAMESPACE":   t.namespace,
		"POLICY_NAME": t.policy,
		"REGISTRY":    t.registry,
	}

	if t.snapshotDigest != "" {
		vars["BUILD_SNAPSHOT_DIGEST"] = t.snapshotDigest
	}

	publicKeys := crypto.PublicKeysFrom(ctx)
	for name, key := range publicKeys {
		vars[fmt.Sprintf("%s_PUBLIC_KEY", name)] = key
	}

	v := os.Expand(value, func(variable string) string {
		return vars[variable]
	})

	return pipeline.Param{
		Name: name,
		Value: pipeline.ParamValue{
			Type:      pipeline.ParamTypeString,
			StringVal: v,
		},
	}
}

// RunTask creates a TaskRun with a random name running the Task from the Tekton
// Bundle of a specific version with the provided parameters
func (k *kindCluster) RunTask(ctx context.Context, version, name, workspace string, params map[string]string) error {
	t := testenv.FetchState[testState](ctx)

	tkn, err := tekton.NewForConfig(k.config)
	if err != nil {
		return err
	}

	tknParams := make([]pipeline.Param, 0, len(params))
	for n, v := range params {
		tknParams = append(tknParams, stringParam(ctx, n, v, t))
	}

	timeout, err := time.ParseDuration("10m")
	if err != nil {
		return err
	}

	var wkspace []pipeline.WorkspaceBinding
	if workspace != "" {
		wkspace = append(wkspace, pipeline.WorkspaceBinding{
			Name:     workspace,
			EmptyDir: &v1.EmptyDirVolumeSource{},
		})
	}

	tr, err := tkn.TaskRuns(t.namespace).Create(ctx, &pipeline.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acceptance-taskrun-",
		},
		Spec: pipeline.TaskRunSpec{
			Workspaces:         wkspace,
			Params:             tknParams,
			ServiceAccountName: "default",
			TaskRef: &pipeline.TaskRef{
				ResolverRef: pipeline.ResolverRef{
					Resolver: "bundles",
					Params: []pipeline.Param{
						stringParam(ctx, "bundle", fmt.Sprintf("registry.image-registry.svc.cluster.local:%d/ec-task-bundle:%s", k.registryPort, version), t),
						stringParam(ctx, "name", name, t),
						stringParam(ctx, "kind", "task", t),
					},
				},
			},
			Timeout: &metav1.Duration{
				Duration: timeout,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// store the TaskRun name in the test context
	t.taskRun = tr.GetName()

	return nil
}

// AwaitUntilTaskIsDone waits for the TaskRun whose name is stored in the test
// context is done and reports if it was successful
func (k *kindCluster) AwaitUntilTaskIsDone(ctx context.Context) (bool, error) {
	t := testenv.FetchState[testState](ctx)

	tkn, err := tekton.NewForConfig(k.config)
	if err != nil {
		return false, err
	}

	watch, err := tkn.TaskRuns(t.namespace).Watch(ctx, metav1.SingleObject(metav1.ObjectMeta{
		Name: t.taskRun,
	}))
	if err != nil {
		return false, err
	}

	for e := range watch.ResultChan() {
		tr, ok := e.Object.(*pipeline.TaskRun)
		if !ok {
			return false, fmt.Errorf("received unexpected object when watching the TaskRun: %v", e.Object.GetObjectKind())
		}

		if tr.IsDone() {
			return tr.IsSuccessful(), nil
		}
	}

	return false, nil
}

// TaskInfo provides information on the TaskRun, invoked after the TaskRun is
// done for most complete information
func (k *kindCluster) TaskInfo(ctx context.Context) (*types.TaskInfo, error) {
	t := testenv.FetchState[testState](ctx)

	tkn, err := tekton.NewForConfig(k.config)
	if err != nil {
		return nil, err
	}

	tr, err := tkn.TaskRuns(t.namespace).Get(ctx, t.taskRun, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	results := map[string]any{}
	for _, r := range tr.Status.Results {
		results[r.Name] = paramValue(r.Value)
	}

	info := types.TaskInfo{
		Namespace: t.namespace,
		Name:      t.taskRun,
		Status:    formatted.Condition(tr.Status.Conditions),
		Results:   results,
	}

	info.Params = map[string]any{}
	for _, p := range tr.Spec.Params {
		info.Params[p.Name] = paramValue(p.Value)
	}

	info.Steps = make([]types.Step, 0, len(tr.Status.Steps))
	for _, s := range tr.Status.Steps {
		logs, err := k.logs(ctx, t.namespace, tr.Status.PodName, s.Container)
		if err != nil {
			return nil, err
		}

		envVars, err := k.envVars(ctx, t.namespace, tr.Status.PodName, s.Container)
		if err != nil {
			return nil, err
		}

		info.Steps = append(info.Steps, types.Step{
			Name:    s.Name,
			Status:  s.TerminationReason,
			Logs:    logs,
			EnvVars: envVars,
		})
	}

	return &info, nil
}

func paramValue(v pipeline.ParamValue) any {
	switch v.Type {
	case pipeline.ParamTypeString:
		return v.StringVal
	case pipeline.ParamTypeArray:
		return v.ArrayVal
	case pipeline.ParamTypeObject:
		return v.ObjectVal
	}

	return "<unset>"
}

func (k *kindCluster) logs(ctx context.Context, namespace, pod, container string) (string, error) {
	stream, err := k.client.CoreV1().Pods(namespace).GetLogs(pod, &v1.PodLogOptions{Container: container}).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()

	bytes, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (k *kindCluster) envVars(ctx context.Context, namespace, podName, containerName string) (map[string]string, error) {
	pod, err := k.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for _, container := range pod.Spec.Containers {
		if container.Name != containerName {
			continue
		}
		envVars := make(map[string]string)
		for _, env := range container.Env {
			envVars[env.Name] = env.Value
		}
		return envVars, nil
	}
	return nil, fmt.Errorf("could not find %q container in %q pod", containerName, podName)
}
