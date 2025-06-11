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

//go:build unit

package validate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ociMetadata "github.com/conforma/go-gather/gather/oci"
	"github.com/gkampitakis/go-snaps/snaps"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
	"github.com/conforma/cli/internal/validate/vsa"
)

type data struct {
	imageRef string
	input    string
	filePath string
	images   string
}

var rootArgs = []string{
	"validate",
	"image",
	"--output",
	"json",
}

func happyValidator() imageValidationFunc {
	return func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSyntaxCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: []evaluator.Outcome{
				{
					FileName:  "test.json",
					Namespace: "test.main",
					Successes: []evaluator.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code":  "policy.nice",
								"title": "Very nice",
							},
						},
					},
				},
			},
			ImageURL: component.ContainerImage,
			ExitCode: 0,
		}, nil
	}
}

func Test_determineInputSpec(t *testing.T) {
	cases := []struct {
		name      string
		arguments data
		spec      *app.SnapshotSpec
		err       string
	}{
		{
			name: "imageRef",
			arguments: data{
				imageRef: "registry/image:tag",
			},
			spec: &app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					{
						Name:           "Unnamed",
						ContainerImage: "registry/image:tag",
					},
				},
			},
		},
		{
			name: "empty ApplicationSnapshot string",
			arguments: data{
				input: "{}",
			},
			spec: &app.SnapshotSpec{},
		},
		{
			name: "faulty ApplicationSnapshot string",
			arguments: data{
				input: "{",
			},
			err: "unable to parse Snapshot specification from {: error converting YAML to JSON: yaml: line 1: did not find expected node content",
		},
		{
			name: "ApplicationSnapshot JSON string - images",
			arguments: data{
				images: `{
					"components": [
					  {
						"name": "nodejs",
						"containerImage": "quay.io/hacbs-contract-demo/single-nodejs-app:877418e"
					  }
					]
				}`,
			},
			spec: &app.SnapshotSpec{
				Application: "",
				Components: []app.SnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot JSON string",
			arguments: data{
				input: `{
					"application": "app1",
					"components": [
					  {
						"name": "nodejs",
						"containerImage": "quay.io/hacbs-contract-demo/single-nodejs-app:877418e"
					  },
					  {
						"name": "petclinic",
						"containerImage": "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f"
					  },
					  {
						"name": "single-container-app",
						"containerImage": "quay.io/hacbs-contract-demo/single-container-app:62c06bf"
					  },
					]
				  }`,
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot YAML string",
			arguments: data{
				input: hd.Doc(`
					---
					application: app1
					components:
					- name: nodejs
					  containerImage: quay.io/hacbs-contract-demo/single-nodejs-app:877418e
					- name: petclinic
					  containerImage: quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f
					- name: single-container-app
					  containerImage: quay.io/hacbs-contract-demo/single-container-app:62c06bf
					`),
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot file",
			arguments: data{
				filePath: "test_application_snapshot.json",
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot file - images",
			arguments: data{
				images: "test_application_snapshot.json",
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
				},
			},
		},
	}
	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := oci.WithClient(context.Background(), &client)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
				File:   c.arguments.filePath,
				JSON:   c.arguments.input,
				Image:  c.arguments.imageRef,
				Images: c.arguments.images,
			})
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, c.spec, s)
		})
	}
}

func Test_ValidateImageCommand(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"success": true
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_ValidateImageCommandImages(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	images := `{
		"components": [
			{
				"name": "bacon",
				"containerImage": "registry.localhost/bacon:v2.0",
				"source": {
					"git": {
						"url": "https://git.localhost/bacon.git",
						"revision": "8abf15bef376e0e21f1f9e9c3d74483d5018f3d5"
					}
				}
			},
			{
				"name": "spam",
				"containerImage": "registry.localhost/spam:v1.0",
				"source": {
					"git": {
						"url": "https://git.localhost/spam.git",
						"revision": "ded982e702e07bb7b6effafdc353db3fe172c83f"
					}
				}
			}
		]
	}`

	cmd.SetArgs(append(rootArgs, []string{
		"--images",
		images,
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
			{
				"name": "spam",
				"containerImage": "registry.localhost/spam:v1.0",
				"source": {
					"git": {
						"url": "https://git.localhost/spam.git",
						"revision": "ded982e702e07bb7b6effafdc353db3fe172c83f"
					}
				},
				"success": true
			},
			{
				"name": "bacon",
				"containerImage": "registry.localhost/bacon:v2.0",
				"source": {
					"git": {
						"url": "https://git.localhost/bacon.git",
						"revision": "8abf15bef376e0e21f1f9e9c3d74483d5018f3d5"
					}
				},
				"success": true
			}
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_ValidateImageCommandKeyless(t *testing.T) {
	called := false
	validateImageCmd := validateImageCmd(func(_ context.Context, _ app.SnapshotComponent, _ *app.SnapshotSpec, p policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		assert.Equal(t, cosign.Identity{
			Issuer:        "my-certificate-oidc-issuer",
			Subject:       "my-certificate-identity",
			IssuerRegExp:  "my-certificate-oidc-issuer-regexp",
			SubjectRegExp: "my-certificate-identity-regexp",
		}, p.Identity())

		called = true

		return &output.Output{}, nil
	})
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		"",
		"--certificate-identity",
		"my-certificate-identity",
		"--certificate-oidc-issuer",
		"my-certificate-oidc-issuer",
		"--certificate-identity-regexp",
		"my-certificate-identity-regexp",
		"--certificate-oidc-issuer-regexp",
		"my-certificate-oidc-issuer-regexp",
	}...))

	utils.SetTestRekorPublicKey(t)
	utils.SetTestFulcioRoots(t)
	utils.SetTestCTLogPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.True(t, called)
}

func Test_ValidateImageCommandYAMLPolicyFile(t *testing.T) {
	cases := []struct {
		name   string
		config string
	}{
		{
			name: "spec",
			config: `
description: My custom enterprise contract policy configuration
sources:
  - policy:
      - quay.io/hacbs-contract/ec-release-policy:latest
    config:
      exclude:
        - not_useful
        - test:conftest-clair
      include:
        - always_checked
        - "@salsa_one_collection"
`,
		},
		{
			name: "ecp",
			config: `
apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  name: enterprisecontractpolicy-sample
spec:
  description: My custom enterprise contract policy configuration
  sources:
    - policy:
        - quay.io/hacbs-contract/ec-release-policy:latest
      config:
        exclude:
          - not_useful
          - test:conftest-clair
        include:
          - always_checked
          - "@salsa_one_collection"
`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validateImageCmd := validateImageCmd(happyValidator())
			cmd := setUpCobra(validateImageCmd)

			client := fake.FakeClient{}
			commonMockClient(&client)
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)
			ctx = oci.WithClient(ctx, &client)

			mdl := MockDownloader{}
			mdl.On("Download", mock.Anything, "quay.io/hacbs-contract/ec-release-policy:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
			ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

			cmd.SetContext(ctx)

			err := afero.WriteFile(fs, "/policy.yaml", []byte(c.config), 0644)
			if err != nil {
				panic(err)
			}
			args := append(rootArgs, []string{
				"--image",
				"registry/image:tag",
				"--public-key",
				utils.TestPublicKey,
				"--policy",
				"/policy.yaml",
				"--effective-time",
				"1970-01-01",
			}...)
			cmd.SetArgs(args)

			var out bytes.Buffer
			cmd.SetOut(&out)

			utils.SetTestRekorPublicKey(t)

			err = cmd.Execute()
			assert.NoError(t, err)

			snaps.MatchJSON(t, out.String())
		})
	}
}

func Test_ValidateImageCommandJSONPolicyFile(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	ctx = oci.WithClient(ctx, &client)

	mdl := MockDownloader{}
	mdl.On("Download", mock.Anything, "registry/policy:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	mdl.On("Download", mock.Anything, "registry/policy-data:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

	cmd.SetContext(ctx)

	testPolicyJSON := `sources:
  - policy:
      - "registry/policy:latest"
    data:
      - "registry/policy-data:latest"
    config:
      include:
        - '@minimal'
      exclude: []
`
	err := afero.WriteFile(fs, "/policy.json", []byte(testPolicyJSON), 0644)
	if err != nil {
		panic(err)
	}
	args := append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.json",
	}...)
	cmd.SetArgs(args)

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_ValidateImageCommandExtraData(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	fs := afero.NewMemMapFs()

	ctx := utils.WithFS(context.Background(), fs)
	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx = oci.WithClient(ctx, &client)

	mdl := MockDownloader{}
	mdl.On("Download", mock.Anything, "registry/policy:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	mdl.On("Download", mock.Anything, "registry/policy-data:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

	cmd.SetContext(ctx)

	testPolicyJSON := `sources:
  - policy:
      - "registry/policy:latest"
    data:
      - "registry/policy-data:latest"
    ruleData:
      custom_rule_data:
        prefix_data:
          - registry1
    config:
      include:
        - '@minimal'
      exclude: []
`
	err := afero.WriteFile(fs, "/policy.json", []byte(testPolicyJSON), 0644)
	if err != nil {
		panic(err)
	}

	testExtraRuleDataYAML := `---
kind: ReleasePlanAdmission
spec:
  application: [some-app]
  data:
    mapping:
      components:
        - name: some-name
          repository: quay.io/some-namespace/msd
`

	err = afero.WriteFile(fs, "/value.yaml", []byte(testExtraRuleDataYAML), 0644)
	if err != nil {
		panic(err)
	}

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.json",
		"--extra-rule-data",
		"key=/value.yaml,key2=value2",
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err = cmd.Execute()
	assert.NoError(t, err)

	// extract one of the sources, since we can match JSON without needing to compare publicKey (which may change)
	unmarshaled := make(map[string]interface{})
	err = json.Unmarshal(out.Bytes(), &unmarshaled)
	assert.NoError(t, err)

	sourceSample := unmarshaled["policy"].(map[string]interface{})["sources"].([]interface{})[0].(map[string]interface{})
	sourceSampleMarshaled, err := json.Marshal(sourceSample)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"data": [
			"oci::registry/policy-data:latest@sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"
		],
		"policy": [
			"oci::registry/policy:latest@sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"
		],
		"ruleData": {
			"custom_rule_data":{"prefix_data":["registry1"]},
			"key": "---\nkind: ReleasePlanAdmission\nspec:\n  application: [some-app]\n  data:\n    mapping:\n      components:\n        - name: some-name\n          repository: quay.io/some-namespace/msd\n",
			"key2": "value2"
		},
		"config": {
		  "include": ["@minimal"]
		}
	  }`, string(sourceSampleMarshaled))
}

func Test_ValidateImageCommandEmptyPolicyFile(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	ctx = oci.WithClient(ctx, &client)

	mdl := MockDownloader{}
	mdl.On("Download", mock.Anything, "registry/policy:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	mdl.On("Download", mock.Anything, "registry/policy-data:latest", false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

	cmd.SetContext(ctx)

	err := afero.WriteFile(fs, "/policy.yaml", []byte(nil), 0644)
	if err != nil {
		panic(err)
	}
	args := append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.yaml",
	}...)
	cmd.SetArgs(args)

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err = cmd.Execute()
	assert.EqualError(t, err, "file /policy.yaml is empty")
}

func Test_ValidateImageError(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name: "image validation failure: incorrect syntax for extraRuleData",
			args: []string{
				"--image",
				"registry/image:tag",
				"--public-key",
				utils.TestPublicKey,
				"--policy",
				"/policy.yaml",
				"--extra-rule-data",
				"key-without-value-1,key-without-value-2",
			},
			expected: "incorrect syntax for --extra-rule-data 0\nincorrect syntax for --extra-rule-data 1",
		},
		{
			name: "image validation failure: unable to load extraRuleData",
			args: []string{
				"--image",
				"registry/image:tag",
				"--public-key",
				utils.TestPublicKey,
				"--policy",
				"/policy.yaml",
				"--extra-rule-data",
				"key=/value.json",
			},
			expected: "unable to load data from extraRuleData: file /value.json is empty",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validateImageCmd := validateImageCmd(happyValidator())
			cmd := setUpCobra(validateImageCmd)

			fs := afero.NewMemMapFs()

			ctx := utils.WithFS(context.Background(), fs)
			client := fake.FakeClient{}
			commonMockClient(&client)
			ctx = oci.WithClient(ctx, &client)

			mdl := MockDownloader{}
			mdl.
				On("Download", mock.Anything, "oci://registry/policy:latest", false).
				Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
			mdl.
				On("Download", mock.Anything, "oci://registry/policy-data:latest", false).
				Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil)
			ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

			cmd.SetContext(ctx)

			testPolicyJSON := `sources:
  - policy:
      - "oci://registry/policy:latest"
    data:
      - "oci://registry/policy-data:latest"
    config:
      include:
        - '@minimal'
      exclude: []
`
			err := afero.WriteFile(fs, "/policy.yaml", []byte(testPolicyJSON), 0644)
			if err != nil {
				panic(err)
			}

			err = afero.WriteFile(fs, "/value.json", []byte(nil), 0644)
			if err != nil {
				panic(err)
			}
			args := append(rootArgs, c.args...)
			cmd.SetArgs(args)

			var out bytes.Buffer
			cmd.SetOut(&out)

			utils.SetTestRekorPublicKey(t)

			err = cmd.Execute()
			assert.EqualError(t, err, c.expected)
		})
	}
}

func Test_ValidateErrorCommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name: "image validation failure",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
			},
			expected: `error validating image registry/image:tag of component Unnamed: expected`,
		},
		{
			name: "invalid policy JSON",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				`{"invalid": "json""}`,
			},
			expected: `unable to parse EnterpriseContractPolicySpec: error converting YAML to JSON: yaml: found unexpected end of stream`,
		},
		{
			name: "invalid input JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
			},
			expected: `unable to parse Snapshot specification from {"invalid": "json""}: error converting YAML to JSON: yaml: found unexpected end of stream`,
		},
		{
			name: "invalid input and policy JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				`{"invalid": "json""}`,
			},
			expected: `unable to parse Snapshot specification from {"invalid": "json""}: error converting YAML to JSON: yaml: found unexpected end of stream
unable to parse EnterpriseContractPolicySpec: error converting YAML to JSON: yaml: found unexpected end of stream`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validate := func(context.Context, app.SnapshotComponent, *app.SnapshotSpec, policy.Policy, []evaluator.Evaluator, bool) (*output.Output, error) {
				return nil, errors.New("expected")
			}

			validateImageCmd := validateImageCmd(validate)
			cmd := setUpCobra(validateImageCmd)

			client := fake.FakeClient{}
			commonMockClient(&client)
			ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
			ctx = oci.WithClient(ctx, &client)
			cmd.SetContext(ctx)

			cmd.SetArgs(append([]string{"validate", "image"}, c.args...))

			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			utils.SetTestRekorPublicKey(t)

			err := cmd.Execute()
			assert.EqualError(t, err, c.expected)
			assert.Empty(t, out.String())
		})
	}
}

func Test_FailureImageAccessibility(t *testing.T) {
	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageURL: component.ContainerImage,
		}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)
	cmd.SilenceUsage = true // The root command is set to prevent usage printouts when running the CLI directly. This setup is temporary workaround.

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"violations": [
			  {"msg": "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			  {"msg": "skipped due to inaccessible image ref"},
			  {"msg": "skipped due to inaccessible image ref"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_FailureOutput(t *testing.T) {
	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "failed image signature check"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "failed attestation signature check"},
			},
			ImageURL: component.ContainerImage,
		}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)
	cmd.SilenceUsage = true // The root command is set to prevent usage printouts when running the CLI directly. This setup is temporary workaround.

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"violations": [
			  {"msg": "failed attestation signature check"},
			  {"msg": "failed image signature check"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_WarningOutput(t *testing.T) {
	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: []evaluator.Outcome{
				{
					Warnings: []evaluator.Result{
						{Message: "warning for policy check 1"},
						{Message: "warning for policy check 2"},
					},
				},
			},
			ImageURL: component.ContainerImage,
		}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"warnings": [
				{"msg": "warning for policy check 1"},
				{"msg": "warning for policy check 2"}
			],
			"success": true
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_FailureImageAccessibilityNonStrict(t *testing.T) {
	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, _ []evaluator.Evaluator, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: false,
				Result: &evaluator.Result{Message: "Image URL is not accessible: HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			},
			ImageURL: component.ContainerImage,
		}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)
	cmd.SilenceUsage = true // The root command is set to prevent usage printouts when running the CLI directly. This setup is temporary workaround.

	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs,
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
		"--strict",
		"false",
		"--ignore-rekor",
		"true"))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.EqualError(t, err, "success criteria not met")
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"violations": [
			  {"msg": "Image URL is not accessible: HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func TestValidateImageCommand_RunE(t *testing.T) {
	validateImageCmd := validateImageCmd(happyValidator())
	cmd := setUpCobra(validateImageCmd)

	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx = oci.WithClient(ctx, &client)
	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs(append(rootArgs, []string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	}...))

	var out bytes.Buffer
	cmd.SetOut(&out)

	utils.SetTestRekorPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"success": true
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func TestValidateImageDefaultOutput(t *testing.T) {
	commonArgs := []string{
		"validate",
		"image",
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
	}

	commonOutput := hd.Doc(`
		Success: true
		Result: SUCCESS
		Violations: 0, Warnings: 0, Successes: 1
		Component: Unnamed
		ImageRef: registry/image:tag

	`)

	cases := []struct {
		args     []string
		expected string
	}{
		{
			args:     commonArgs,
			expected: commonOutput,
		},
		{
			args: append(commonArgs, "--show-successes"),
			expected: fmt.Sprintf("%s%s", commonOutput, hd.Doc(`
				Results:
				✓ [Success] policy.nice
				  ImageRef: registry/image:tag
				  Title: Very nice

			`)),
		},
	}

	for _, c := range cases {
		validateImageCmd := validateImageCmd(happyValidator())
		cmd := setUpCobra(validateImageCmd)

		ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
		client := fake.FakeClient{}
		commonMockClient(&client)
		ctx = oci.WithClient(ctx, &client)
		cmd.SetContext(ctx)

		// Notice there is no --output flag here
		cmd.SetArgs(c.args)

		var out bytes.Buffer
		cmd.SetOut(&out)

		utils.SetTestRekorPublicKey(t)

		err := cmd.Execute()
		assert.NoError(t, err)

		assert.Equal(t, c.expected, out.String())
	}
}

// TestContainsData validates containsData behavior
func TestContainsData(t *testing.T) {
	tests := []struct {
		input    []string
		expected bool
		name     string
	}{
		{[]string{"data"}, true, "Match single data"},
		{[]string{"data=something"}, true, "Match data=something"},
		{[]string{"text=data-file.txt"}, false, "Do not match text=data-file.txt"},
		{[]string{"json", "data=custom-data.yaml"}, true, "Match data in slice with multiple values"},
		{[]string{"data text"}, false, "Do not match data text"},
		{[]string{"dat"}, false, "Do not match dat"},
		{[]string{"data123"}, false, "Do not match data123"},
		{[]string{"data="}, true, "Match data="},
		{[]string{""}, false, "Do not match empty string"},
	}

	for _, test := range tests {
		result := containsOutput(test.input, "data")
		assert.Equal(t, test.expected, result, test.name)
	}
}

func TestContainsAttestation(t *testing.T) {
	tests := []struct {
		input    []string
		expected bool
		name     string
	}{
		{[]string{"attestation"}, true, "Match single attestation"},
		{[]string{"attestation=some-file.att"}, true, "Match attestation=some-file.att"},
		{[]string{"meta=attestation.json"}, false, "Do not match meta=attestation.json"},
		{[]string{"config", "attestation=custom-attestation.yaml"}, true, "Match attestation in slice with multiple values"},
		{[]string{"attestation text"}, false, "Do not match attestation text"},
		{[]string{"attest"}, false, "Do not match attest"},
		{[]string{"attestation123"}, false, "Do not match attestation123"},
		{[]string{"attestation="}, true, "Match attestation="},
		{[]string{""}, false, "Do not match empty string"},
	}

	for _, test := range tests {
		result := containsOutput(test.input, "attestation")
		assert.Equal(t, test.expected, result, test.name)
	}
}

// --- Mocks and tests for processVSAForComponent ---

type mockGenerator struct {
	GeneratePredicateFunc func(ctx context.Context, comp applicationsnapshot.Component) (*vsa.Predicate, error)
}

func (m *mockGenerator) GeneratePredicate(ctx context.Context, comp applicationsnapshot.Component) (*vsa.Predicate, error) {
	return m.GeneratePredicateFunc(ctx, comp)
}

type mockWriter struct {
	WriteVSAFunc func(pred *vsa.Predicate) (string, error)
}

func (m *mockWriter) WriteVSA(pred *vsa.Predicate) (string, error) {
	return m.WriteVSAFunc(pred)
}

type mockAttestor struct {
	AttestPredicateFunc func(ctx context.Context) ([]byte, error)
	WriteEnvelopeFunc   func(data []byte) (string, error)
}

func (m *mockAttestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	return m.AttestPredicateFunc(ctx)
}

func (m *mockAttestor) WriteEnvelope(data []byte) (string, error) {
	return m.WriteEnvelopeFunc(data)
}

func Test_attestVSA_success(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}

	attestor := &mockAttestor{
		AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
			return []byte("envelope"), nil
		},
		WriteEnvelopeFunc: func(data []byte) (string, error) {
			if string(data) != "envelope" {
				t.Errorf("unexpected data passed to WriteEnvelope")
			}
			return "/tmp/envelope.json", nil
		},
	}

	path, err := attestVSA(ctx, attestor, comp)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/envelope.json", path)
}

func Test_attestVSA_errors(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}

	t.Run("attest predicate fails", func(t *testing.T) {
		attestor := &mockAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return nil, errors.New("attest error")
			},
		}
		path, err := attestVSA(ctx, attestor, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error attesting VSA")
		assert.Empty(t, path)
	})

	t.Run("write envelope fails", func(t *testing.T) {
		attestor := &mockAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return []byte("envelope"), nil
			},
			WriteEnvelopeFunc: func(data []byte) (string, error) {
				return "", errors.New("envelope error")
			},
		}
		path, err := attestVSA(ctx, attestor, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error writing envelope")
		assert.Empty(t, path)
	})
}

func Test_generateAndWrite_success(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}
	pred := &vsa.Predicate{ImageRef: "test-image"}

	gen := &mockGenerator{
		GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*vsa.Predicate, error) {
			return pred, nil
		},
	}
	writer := &mockWriter{
		WriteVSAFunc: func(p *vsa.Predicate) (string, error) {
			if p != pred {
				t.Errorf("unexpected predicate passed to WriteVSA")
			}
			return "/tmp/vsa.json", nil
		},
	}

	path, err := generateAndWrite(ctx, gen, writer, comp)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/vsa.json", path)
}

func Test_generateAndWrite_errors(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}
	pred := &vsa.Predicate{ImageRef: "test-image"}

	t.Run("predicate generation fails", func(t *testing.T) {
		gen := &mockGenerator{
			GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*vsa.Predicate, error) {
				return nil, errors.New("predicate generation error")
			},
		}
		writer := &mockWriter{}

		path, err := generateAndWrite(ctx, gen, writer, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "predicate generation error")
		assert.Empty(t, path)
	})

	t.Run("write VSA fails", func(t *testing.T) {
		gen := &mockGenerator{
			GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*vsa.Predicate, error) {
				return pred, nil
			},
		}
		writer := &mockWriter{
			WriteVSAFunc: func(p *vsa.Predicate) (string, error) {
				return "", errors.New("write VSA error")
			},
		}

		path, err := generateAndWrite(ctx, gen, writer, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write VSA error")
		assert.Empty(t, path)
	})
}
