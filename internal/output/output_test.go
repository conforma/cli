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

package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/signature"
	"github.com/conforma/cli/internal/utils"
)

func Test_PrintExpectedJSON(t *testing.T) {
	output := Output{
		ImageSignatureCheck: VerificationStatus{
			Passed: true,
			Result: &evaluator.Result{Message: "message1"},
		},
		ImageAccessibleCheck: VerificationStatus{
			Passed: true,
			Result: &evaluator.Result{Message: "message2"},
		},
		AttestationSignatureCheck: VerificationStatus{
			Passed: false,
			Result: &evaluator.Result{Message: "message3"},
		},
		AttestationSyntaxCheck: VerificationStatus{
			Passed: false,
			Result: &evaluator.Result{Message: "message4"},
		},
		PolicyCheck: []evaluator.Outcome{
			{
				FileName:  "file1.json",
				Namespace: "namespace1",
				Skipped: []evaluator.Result{
					{Message: "result11"},
					{Message: "result12"},
				},
				Warnings: []evaluator.Result{
					{Message: "result13"},
					{Message: "result14"},
				},
				Failures: []evaluator.Result{
					{Message: "result15"},
				},
				Exceptions: []evaluator.Result{},
				Successes: []evaluator.Result{
					{Message: "result16"},
					{Message: "result17"},
				},
			},
			{
				FileName:  "file2.json",
				Namespace: "namespace2",
				Skipped: []evaluator.Result{
					{
						Message: "result21",
					},
				},
				Successes: []evaluator.Result{
					{Message: "result22"},
				},
			},
		},
		Signatures: []signature.EntitySignature{
			{KeyID: "key-id", Signature: "signature"},
		},
		ExitCode: 42,
	}

	var json bytes.Buffer
	output.Print(&json)

	assert.JSONEq(t, `{
		"imageSignatureCheck": {
		  "passed": true,
		  "result": {
		    "msg": "message1"
		  }
		},
		"imageAccessibleCheck": {
		  "passed": true,
		  "result": {
		    "msg": "message2"
		  }
		},
		"attestationSignatureCheck": {
		  "passed": false,
		  "result": {
		    "msg": "message3"
		  }
		},
		"attestationSyntaxCheck": {
		  "passed": false,
		  "result": {
		    "msg": "message4"
		  }
		},
		"policyCheck": [
		  {
			"filename": "file1.json",
			"namespace": "namespace1",
			"skipped": [
			  {
				"msg": "result11"
			  },
			  {
				"msg": "result12"
			  }
			],
			"warnings": [
			  {
				"msg": "result13"
			  },
			  {
				"msg": "result14"
			  }
			],
			"failures": [
			  {
				"msg": "result15"
			  }
			],
			"successes": [
			  {
				"msg": "result16"
			  },
			  {
				"msg": "result17"
			  }
			]
		  },
		  {
			"filename": "file2.json",
			"namespace": "namespace2",
			"skipped": [
			  {
				"msg": "result21"
			  }
			],
			"successes": [
			  {
			    "msg": "result22"
			  }
			]
		  }
		],
		"signatures": [{"keyid": "key-id", "sig": "signature"}]
	  }`, json.String())
}

func Test_PrintOutputsExpectedJSON(t *testing.T) {
	// we don't care much about content as much as the JSON encoding is correct
	outputs := Outputs{
		{},
		{},
	}

	var buff bytes.Buffer

	outputs.Print(&buff)

	assert.JSONEq(t, `[
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "imageAccessibleCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "attestationSyntaxCheck": {
			"passed": false
		  },
		  "policyCheck": null
		},
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "imageAccessibleCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "attestationSyntaxCheck": {
			"passed": false
		  },
		  "policyCheck": null
		}
	  ]`, buff.String())
}

func Test_Violations(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected []evaluator.Result
	}{
		{
			name: "passing",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []evaluator.Result{},
		},
		{
			name: "failing image signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "image signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []evaluator.Result{{Message: "image signature failed"}},
		},
		{
			name: "failing attestation signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []evaluator.Result{{Message: "attestation signature failed"}},
		},
		{
			name: "failing attestation signature",
			output: Output{
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "attestation signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "image signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []evaluator.Result{
				{Message: "attestation signature failed"},
				{Message: "image signature failed"},
			},
		},
		{
			name: "failing policy check",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{
								Message: "failed policy check",
							},
						},
					},
				},
			},
			expected: []evaluator.Result{{Message: "failed policy check"}},
		},
		{
			name: "failing multiple policy checks",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{
								Message: "failed policy check 1",
							},
							{
								Message: "failed policy check 2",
							},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "failed policy check 1"},
				{Message: "failed policy check 2"},
			},
		},
		{
			name: "failing everything",
			output: Output{
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "attestation signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{
								Message: "failed policy check 1",
							},
							{
								Message: "failed policy check 2",
							},
						},
					},
				},
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "image signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "invalid attestation syntax"},
				},
			},
			expected: []evaluator.Result{
				{Message: "attestation signature failed"},
				{Message: "failed policy check 1"},
				{Message: "failed policy check 2"},
				{Message: "image signature failed"},
				{Message: "invalid attestation syntax"},
			},
		},
		{
			name: "mixed results",
			output: Output{
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []evaluator.Outcome{
					// Result with failures
					{
						Failures: []evaluator.Result{
							{Message: "failure for policy check 1"},
							{Message: "failure for policy check 2"},
						},
					},
					// Result with warnings
					{
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 3"},
							{Message: "warning for policy check 4"},
						},
					},
					// Result without any failures nor warnings
					{},
					// Resuilt with both failures and warnings
					{
						Failures: []evaluator.Result{
							{Message: "failure for policy check 5"},
							{Message: "failure for policy check 6"},
						},
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 7"},
							{Message: "warning for policy check 8"},
						},
					},
					// Result with successes
					{
						Successes: []evaluator.Result{
							{Message: "success for policy check 9"},
						},
					},
				},
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "image signature failed"},
				},
			},
			expected: []evaluator.Result{
				{Message: "attestation signature failed"},
				{Message: "failure for policy check 1"},
				{Message: "failure for policy check 2"},
				{Message: "failure for policy check 5"},
				{Message: "failure for policy check 6"},
				{Message: "image signature failed"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.Violations())
		})
	}
}

func Test_Successes(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected []evaluator.Result
	}{
		{
			name: "passing",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					}},
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.signature_check",
						"title": "Attestation signature check passed",
					}},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "image accessible passed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.syntax_check",
						"title": "Attestation syntax check passed",
					}},
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Successes: []evaluator.Result{
							{
								Message: "passed policy check",
							},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "passed policy check"},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.signature_check",
					"title": "Attestation signature check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.syntax_check",
					"title": "Attestation syntax check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.image.signature_check",
					"title": "Image signature check passed",
				}},
			},
		},
		{
			name: "failing image signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "Image signature check failed", Metadata: map[string]interface{}{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					}},
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.signature_check",
						"title": "Attestation signature check passed",
					}},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "image accessible passed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.syntax_check",
						"title": "Attestation syntax check passed",
					}},
				},
			},
			expected: []evaluator.Result{
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.signature_check",
					"title": "Attestation signature check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.syntax_check",
					"title": "Attestation syntax check passed",
				}},
			},
		},
		{
			name: "failing attestation signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					}},
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &evaluator.Result{Message: "Attestation check failed", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.signature_check",
						"title": "Attestation signature check passed",
					}},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "image accessible passed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.syntax_check",
						"title": "Attestation syntax check passed",
					}},
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Successes: []evaluator.Result{
							{
								Message: "passed policy check",
							},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "passed policy check"},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.syntax_check",
					"title": "Attestation syntax check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.image.signature_check",
					"title": "Image signature check passed",
				}},
			},
		},
		{
			name: "failing policy check",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					}},
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.signature_check",
						"title": "Attestation signature check passed",
					}},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "image accessible passed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
					Result: &evaluator.Result{Message: "Pass", Metadata: map[string]interface{}{
						"code":  "builtin.attestation.syntax_check",
						"title": "Attestation syntax check passed",
					}},
				},
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{
								Message: "failed policy check",
							},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.signature_check",
					"title": "Attestation signature check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.attestation.syntax_check",
					"title": "Attestation syntax check passed",
				}},
				{Message: "Pass", Metadata: map[string]interface{}{
					"code":  "builtin.image.signature_check",
					"title": "Image signature check passed",
				}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.Successes())
		})
	}
}

func Test_Warnings(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected []evaluator.Result
	}{
		{
			name:     "no-warnings",
			output:   Output{},
			expected: []evaluator.Result{},
		},
		{
			name: "single warning",
			output: Output{
				PolicyCheck: []evaluator.Outcome{
					{
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "warning for policy check 2"},
			},
		},
		{
			name: "multiple warnings",
			output: Output{
				PolicyCheck: []evaluator.Outcome{
					{
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 1"},
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "warning for policy check 1"},
				{Message: "warning for policy check 2"},
			},
		},
		{
			name: "mixed results",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []evaluator.Outcome{
					// Result with failures
					{
						Failures: []evaluator.Result{
							{Message: "failure for policy check 1"},
							{Message: "failure for policy check 2"},
						},
					},
					// Result with warnings
					{
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 3"},
							{Message: "warning for policy check 4"},
						},
					},
					// Result without any failures nor warnings
					{},
					// Resuilt with both failures and warnings
					{
						Failures: []evaluator.Result{
							{Message: "failure for policy check 5"},
							{Message: "failure for policy check 6"},
						},
						Warnings: []evaluator.Result{
							{Message: "warning for policy check 7"},
							{Message: "warning for policy check 8"},
						},
					},
				},
			},
			expected: []evaluator.Result{
				{Message: "warning for policy check 3"},
				{Message: "warning for policy check 4"},
				{Message: "warning for policy check 7"},
				{Message: "warning for policy check 8"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.Warnings())
		})
	}
}

func TestSetImageAccessibleCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *evaluator.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
			expectedResult: &evaluator.Result{
				Message: "Pass",
				Metadata: map[string]interface{}{
					"code": "builtin.image.accessible",
				},
			},
		},
		{
			name:           "failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &evaluator.Result{
				Message: "Image URL is not accessible: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.image.accessible",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetImageAccessibleCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.ImageAccessibleCheck.Passed)
			assert.Equal(t, c.expectedResult, o.ImageAccessibleCheck.Result)
		})
	}
}

func TestSetImageSignatureCheckFromError(t *testing.T) {
	noMatchingSignatures := cosign.ErrNoMatchingSignatures{}
	f := reflect.ValueOf(&noMatchingSignatures).Elem().Field(0)
	f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem() //nolint:gosec // G115 - seems to be a false positive
	f.Set(reflect.ValueOf(errors.New("kaboom!")))

	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *evaluator.Result
		policy         func(context.Context) policy.Policy
	}{
		{
			name:           "success",
			expectedPassed: true,
			expectedResult: &evaluator.Result{
				Message: "Pass",
				Metadata: map[string]interface{}{
					"code": "builtin.image.signature_check",
				},
			},
		},
		{
			name:           "generic failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &evaluator.Result{
				Message: "Image signature check failed: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.image.signature_check",
				},
			},
		},
		{
			name:           "missing signatures failure",
			expectedPassed: false,
			err:            &noMatchingSignatures,
			expectedResult: &evaluator.Result{
				Message: fmt.Sprintf(missingSignatureMessage, &noMatchingSignatures),
				Metadata: map[string]interface{}{
					"code": "builtin.image.signature_check",
				},
			},
		},
		{
			name:           "missing signatures failure with keyless",
			expectedPassed: false,
			err:            &noMatchingSignatures,
			expectedResult: &evaluator.Result{
				Message: "Image signature check failed: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.image.signature_check",
				},
			},
			policy: func(ctx context.Context) policy.Policy {
				p, err := policy.NewPolicy(ctx, policy.Options{
					EffectiveTime: policy.Now,
					Identity:      cosign.Identity{Issuer: "issuer", Subject: "subject"},
				})
				require.NoError(t, err)
				return p
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			var p policy.Policy
			if c.policy != nil {
				utils.SetTestRekorPublicKey(t)
				utils.SetTestFulcioRoots(t)
				utils.SetTestCTLogPublicKey(t)
				p = c.policy(ctx)
			}

			o := Output{Policy: p}
			o.SetImageSignatureCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.ImageSignatureCheck.Passed)
			assert.Equal(t, c.expectedResult, o.ImageSignatureCheck.Result)
		})
	}
}

func TestSetAttestationSignatureCheckFromError(t *testing.T) {
	noMatchingAttestations := cosign.ErrNoMatchingAttestations{}
	f := reflect.ValueOf(&noMatchingAttestations).Elem().Field(0)
	f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem() //nolint:gosec // G115 - seems to be a false positive
	f.Set(reflect.ValueOf(errors.New("kaboom!")))

	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *evaluator.Result
		policy         func(context.Context) policy.Policy
	}{
		{
			name:           "success",
			expectedPassed: true,
			expectedResult: &evaluator.Result{
				Message: "Pass",
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.signature_check",
				},
			},
		},
		{
			name:           "generic failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &evaluator.Result{
				Message: "Image attestation check failed: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.signature_check",
				},
			},
		},
		{
			name:           "missing attestations failure",
			expectedPassed: false,
			err:            &noMatchingAttestations,
			expectedResult: &evaluator.Result{
				Message: fmt.Sprintf(missingAttestationMessage, &noMatchingAttestations),
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.signature_check",
				},
			},
		},
		{
			name:           "missing attestations failure with keyless",
			expectedPassed: false,
			err:            &noMatchingAttestations,
			expectedResult: &evaluator.Result{
				Message: "Image attestation check failed: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.signature_check",
				},
			},
			policy: func(ctx context.Context) policy.Policy {
				p, err := policy.NewPolicy(ctx, policy.Options{
					EffectiveTime: policy.Now,
					Identity:      cosign.Identity{Issuer: "issuer", Subject: "subject"},
				})
				require.NoError(t, err)
				return p
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			var p policy.Policy
			if c.policy != nil {
				utils.SetTestRekorPublicKey(t)
				utils.SetTestFulcioRoots(t)
				utils.SetTestCTLogPublicKey(t)
				p = c.policy(ctx)
			}

			o := Output{Policy: p}
			o.SetAttestationSignatureCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.AttestationSignatureCheck.Passed)
			assert.Equal(t, c.expectedResult, o.AttestationSignatureCheck.Result)
		})
	}
}

func TestSetAttestationSyntaxCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *evaluator.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
			expectedResult: &evaluator.Result{
				Message: "Pass",
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.syntax_check",
				},
			},
		},
		{
			name:           "failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &evaluator.Result{
				Message: "Attestation syntax check failed: kaboom!",
				Metadata: map[string]interface{}{
					"code": "builtin.attestation.syntax_check",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetAttestationSyntaxCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.AttestationSyntaxCheck.Passed)
			assert.Equal(t, c.expectedResult, o.AttestationSyntaxCheck.Result)
		})
	}
}

func TestKeepSomeMetadataSingle(t *testing.T) {
	cases := []struct {
		name             string
		input            evaluator.Result
		expectedMetadata map[string]interface{}
	}{
		{
			name: "preserves required metadata including pipeline_intention",
			input: evaluator.Result{
				Message: "Test message",
				Metadata: map[string]interface{}{
					"code":               "test.rule",
					"effective_on":       "2023-01-01",
					"term":               "test-term",
					"pipeline_intention": []string{"release", "production"},
					"title":              "Test Rule Title",
					"description":        "Test Rule Description",
					"some_other_key":     "should be removed",
				},
			},
			expectedMetadata: map[string]interface{}{
				"code":               "test.rule",
				"effective_on":       "2023-01-01",
				"term":               "test-term",
				"pipeline_intention": []string{"release", "production"},
			},
		},
		{
			name: "preserves basic metadata without pipeline_intention",
			input: evaluator.Result{
				Message: "Test message",
				Metadata: map[string]interface{}{
					"code":           "test.rule",
					"effective_on":   "2023-01-01",
					"title":          "Test Rule Title",
					"description":    "Test Rule Description",
					"some_other_key": "should be removed",
				},
			},
			expectedMetadata: map[string]interface{}{
				"code":         "test.rule",
				"effective_on": "2023-01-01",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Make a copy to avoid modifying the original
			result := evaluator.Result{
				Message:  tc.input.Message,
				Metadata: make(map[string]interface{}),
			}
			for k, v := range tc.input.Metadata {
				result.Metadata[k] = v
			}

			// Apply the function
			keepSomeMetadataSingle(result)

			// Verify the result
			assert.Equal(t, tc.expectedMetadata, result.Metadata)
		})
	}
}
