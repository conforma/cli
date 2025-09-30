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

package policy

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc/v2"
	ecc "github.com/conforma/crds/api/v1alpha1"
	fileMetadata "github.com/conforma/go-gather/gather/file"
	"github.com/conforma/go-gather/metadata"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignSig "github.com/sigstore/cosign/v2/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/kubernetes"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

func TestNewPolicy(t *testing.T) {
	timeNowStr := "2022-11-23T16:30:00Z"
	timeNow, err := time.Parse(time.RFC3339, timeNowStr)
	assert.NoError(t, err)

	cases := []struct {
		name        string
		policyRef   string
		k8sResource *ecc.EnterpriseContractPolicySpec
		rekorUrl    string
		publicKey   string
		k8sError    bool
		expected    *policy
		expectErr   bool
		errorCause  string
	}{
		// Successful scenarios
		{
			name:      "simple JSON inline",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name: "k8s JSON inline",
			policyRef: toJson(&ecc.EnterpriseContractPolicy{
				TypeMeta: v1.TypeMeta{
					APIVersion: "appstudio.redhat.com/v1alpha1",
					Kind:       "EnterpriseContractPolicy",
				}, Spec: ecc.EnterpriseContractPolicySpec{
					PublicKey: utils.TestPublicKey,
				},
			}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "simple YAML inline",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name: "k8s YAML inline",
			policyRef: toYAML(&ecc.EnterpriseContractPolicy{
				TypeMeta: v1.TypeMeta{
					APIVersion: "appstudio.redhat.com/v1alpha1",
					Kind:       "EnterpriseContractPolicy",
				}, Spec: ecc.EnterpriseContractPolicySpec{
					PublicKey: utils.TestPublicKey,
				},
			}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "JSON inline with public key overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "YAML inline with public key overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "JSON inline with rekor URL",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "YAML inline with rekor URL",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "JSON inline with rekor URL overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "YAML inline with rekor URL overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:        "simple k8sPath",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:        "k8sPath with public key overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"},
			publicKey:   utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:        "k8sPath with rekor URL",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:        "k8sPath with rekor overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey},
			rekorUrl:    utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		{
			name:      "default empty policy",
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey,
			}, effectiveTime: &timeNow, choosenTime: timeNowStr},
			expectErr: false,
		},
		// Failure scenarios
		{
			name:       "invalid inline JSON",
			policyRef:  `{"invalid": "json""}`,
			expectErr:  true,
			errorCause: "unable to parse",
		},
		{
			name: "invalid inline YAML",
			policyRef: hd.Doc(`
				---
				invalid: yaml
				  spam:
				`),
			expectErr:  true,
			errorCause: "unable to parse",
		},
		{
			name:       "unable to fetch resource",
			policyRef:  "ec-policy",
			k8sError:   true,
			expectErr:  true,
			errorCause: "unable to fetch",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			// Setup fake client to simulate external connections
			if c.k8sResource != nil {
				ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{Policy: *c.k8sResource})
			} else if c.k8sError {
				ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{FetchError: c.k8sError})
			}

			utils.SetTestRekorPublicKey(t)

			got, err := NewPolicy(ctx, Options{
				PolicyRef:     c.policyRef,
				RekorURL:      c.rekorUrl,
				PublicKey:     c.publicKey,
				EffectiveTime: timeNowStr,
			})

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid policy options")
				if c.errorCause != "" {
					assert.ErrorContains(t, err, c.errorCause)
				}
				assert.Nil(t, got, "Policy should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for valid policy options")
				assert.NotNil(t, got, "Policy should not be nil for successful creation")

				// CheckOpts is more thoroughly checked in TestCheckOpts
				got.(*policy).checkOpts = nil
				assert.Equal(t, c.expected.EffectiveTime(), got.EffectiveTime())

				c.expected.effectiveTime = nil
				got.(*policy).effectiveTime = nil

				assert.Equal(t, c.expected, got)
			}
		})
	}
}

func TestCheckOpts(t *testing.T) {
	cases := []struct {
		name            string
		policyRef       string
		rekorUrl        string
		ignoreRekor     bool
		publicKey       string
		remotePublicKey string
		identity        cosign.Identity
		expectKeyless   bool
		err             string
	}{
		{
			//Public Key Workflow Tests: Rekor client creation
			name:      "create rekor client",
			rekorUrl:  utils.TestRekorURL,
			publicKey: utils.TestPublicKey,
		},
		{
			//Public Key Workflow Tests: inline key handling
			name:      "inline public key",
			publicKey: utils.TestPublicKey,
		},
		{
			//Public Key Workflow Tests: remote key fetching via k8s://
			name:            "in-cluster public key",
			publicKey:       "k8s://test/cosign-public-key",
			remotePublicKey: utils.TestPublicKey,
		},
		{
			//Public Key Workflow Tests: Rekor public key setup
			name:      "with rekor public key",
			rekorUrl:  utils.TestRekorURL,
			publicKey: utils.TestPublicKey,
		},
		{
			//Public Key Workflow Tests: ignoreRekor: true scenario
			name:        "without rekor",
			ignoreRekor: true,
			publicKey:   utils.TestPublicKey,
		},
		{
			name:          "keyless",
			rekorUrl:      utils.TestRekorURL,
			expectKeyless: true,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name:          "keyless without rekor",
			ignoreRekor:   true,
			expectKeyless: true,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name:          "keyless with regexp issuer",
			rekorUrl:      utils.TestRekorURL,
			expectKeyless: true,
			identity: cosign.Identity{
				IssuerRegExp: "my-issuer-regexp",
				Subject:      "my-subject",
			},
		},
		{
			name:          "keyless with regexp subject",
			rekorUrl:      utils.TestRekorURL,
			expectKeyless: true,
			identity: cosign.Identity{
				Issuer:        "my-issuer",
				SubjectRegExp: "my-subject-regexp",
			},
		},
		{
			name:          "keyless with regexp issuer and subject",
			rekorUrl:      utils.TestRekorURL,
			expectKeyless: true,
			identity: cosign.Identity{
				IssuerRegExp:  "my-issuer-regexp",
				SubjectRegExp: "my-subject-regexp",
			},
		},
		{
			name:          "prioritize public key worklow",
			rekorUrl:      utils.TestRekorURL,
			publicKey:     utils.TestPublicKey,
			expectKeyless: false,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name: "keyless missing issuer",
			err:  "certificate OIDC issuer must be provided for keyless workflow",
			identity: cosign.Identity{
				Subject: "my-subject",
			},
		},
		{
			name: "keyless missing subject",
			err:  "certificate identity must be provided for keyless workflow",
			identity: cosign.Identity{
				Issuer: "my-issuer",
			},
		},
		{
			name:      "keyless missing issuer in ECP",
			err:       "certificate OIDC issuer must be provided for keyless workflow",
			policyRef: `{"identity": {"subject": "my-subject"}}`,
		},
		{
			name:      "keyless missing subject in ECP",
			err:       "certificate identity must be provided for keyless workflow",
			policyRef: `{"identity": {"issuer": "my-issuer"}}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = withSignatureClient(ctx, &FakeCosignClient{publicKey: c.remotePublicKey})
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			p, err := NewPolicy(ctx, Options{
				PolicyRef:     c.policyRef,
				RekorURL:      c.rekorUrl,
				IgnoreRekor:   c.ignoreRekor,
				PublicKey:     c.publicKey,
				EffectiveTime: Now,
				Identity:      c.identity,
			})
			if c.err != "" {
				assert.Empty(t, p)
				assert.ErrorContains(t, err, c.err)
				return
			}
			assert.NoError(t, err)

			opts, err := p.CheckOpts()
			assert.NoError(t, err)

			if c.ignoreRekor {
				assert.Nil(t, opts.RekorPubKeys)
				assert.Nil(t, opts.RekorClient)
				assert.True(t, opts.IgnoreTlog)
			} else {
				assert.False(t, opts.IgnoreTlog)
				assert.NotNil(t, opts.RekorPubKeys)
				_, present := opts.RekorPubKeys.Keys[utils.TestRekorURLLogID]
				assert.True(t, present, "Expecting specific log id based on the provided public key")

				if c.rekorUrl != "" {
					assert.NotNil(t, opts.RekorClient)
				} else {
					assert.Nil(t, opts.RekorClient)
				}
			}

			if c.expectKeyless {
				assert.Empty(t, opts.SigVerifier)
				assert.Equal(t, opts.Identities, []cosign.Identity{c.identity})
				assert.NotEmpty(t, opts.RootCerts)
				assert.NotEmpty(t, opts.IntermediateCerts)
				assert.NotEmpty(t, opts.CTLogPubKeys)
			} else {
				assert.NotEmpty(t, opts.SigVerifier)
				assert.Empty(t, opts.Identities)
				assert.Empty(t, opts.RootCerts)
				assert.Empty(t, opts.IntermediateCerts)
				assert.Empty(t, opts.CTLogPubKeys)
			}
		})
	}
}

func TestPublicKeyPEM(t *testing.T) {
	cases := []struct {
		name              string
		remotePublicKey   string
		newPolicy         func(context.Context) (Policy, error)
		expectedPublicKey string
		err               string
	}{
		{
			name: "public key",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{PublicKey: utils.TestPublicKey, EffectiveTime: Now})
			},
			expectedPublicKey: utils.TestPublicKey,
		},
		{
			name: "checkOpts is nil",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewInertPolicy(ctx, fmt.Sprintf(`{"publicKey": "%s"}`, utils.TestPublicKey))
			},
			err: "no check options or sig verifier configured",
		},
		{
			name: "keyless",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{
					EffectiveTime: Now,
					Identity: cosign.Identity{
						Subject: "my-subject", Issuer: "my-issuer",
					},
				})
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			p, err := c.newPolicy(ctx)
			assert.NoError(t, err)

			publicKeyPEM, err := p.PublicKeyPEM()
			if c.err != "" {
				assert.ErrorContains(t, err, c.err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t,
				strings.TrimSpace(c.expectedPublicKey),
				strings.TrimSpace(string(publicKeyPEM)))
		})
	}
}

func TestIdentity(t *testing.T) {
	cases := []struct {
		name             string
		newPolicy        func(context.Context) (Policy, error)
		expectedIdentity cosign.Identity
		err              string
	}{
		{
			name: "identity from Options",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{
					EffectiveTime: Now,
					Identity: cosign.Identity{
						Subject: "my-subject", Issuer: "my-issuer",
					},
				})
			},
			expectedIdentity: cosign.Identity{Subject: "my-subject", Issuer: "my-issuer"},
		},
		{
			name: "identity from Options with regexp",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{
					EffectiveTime: Now,
					Identity: cosign.Identity{
						SubjectRegExp: "subject-.*", IssuerRegExp: "issuer-.*",
					},
				})
			},
			expectedIdentity: cosign.Identity{SubjectRegExp: "subject-.*", IssuerRegExp: "issuer-.*"},
		},
		{
			name: "identity from ECP",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{
					PolicyRef:     `{"identity": {"subject": "my-subject", "issuer": "my-issuer"}}`,
					EffectiveTime: Now,
				})
			},
			expectedIdentity: cosign.Identity{Subject: "my-subject", Issuer: "my-issuer"},
		},
		{
			name: "identity from ECP with regexp",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, Options{
					PolicyRef:     `{"identity": {"subjectRegExp": "subject-.*", "issuerRegExp": "issuer-.*"}}`,
					EffectiveTime: Now,
				})
			},
			expectedIdentity: cosign.Identity{SubjectRegExp: "subject-.*", IssuerRegExp: "issuer-.*"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			p, err := c.newPolicy(ctx)
			assert.NoError(t, err)
			assert.Equal(t, p.Identity(), c.expectedIdentity)
		})
	}
}

func TestParseEffectiveTime(t *testing.T) {
	_, err := parseEffectiveTime("")
	assert.ErrorContains(t, err, "invalid policy time argument")

	effective, err := parseEffectiveTime(Now)
	assert.NoError(t, err)
	assert.Equal(t, time.UTC, effective.Location())

	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	effective, err = parseEffectiveTime(Now)
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, epoch, *effective)

	effective, err = parseEffectiveTime("2001-02-03T04:05:06+07:00")
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, time.Date(2001, 2, 2, 21, 5, 6, 0, time.UTC), *effective)

	effective, err = parseEffectiveTime("2001-02-03")
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC), *effective)

	effective, err = parseEffectiveTime("attestation")
	assert.NoError(t, err)
	assert.Nil(t, effective)
}

func TestEffectiveTimeNowNoMutation(t *testing.T) {
	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	p, err := NewOfflinePolicy(context.Background(), Now)
	assert.NoError(t, err)

	assert.Equal(t, epoch, p.EffectiveTime())

	p.AttestationTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, epoch, p.EffectiveTime())
}

func TestEffectiveTimeGivenNoMutation(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()

	p, err := NewOfflinePolicy(context.Background(), epoch.Format(time.RFC3339))
	assert.NoError(t, err)

	assert.Equal(t, epoch, p.EffectiveTime())

	p.AttestationTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, epoch, p.EffectiveTime())
}

func TestEffectiveTimeAttestationAllowMutation(t *testing.T) {
	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	p, err := NewOfflinePolicy(context.Background(), AtAttestation)
	assert.NoError(t, err)

	// falling back to now, as attestation time hasn't been set
	assert.Equal(t, epoch, p.EffectiveTime())

	attestation := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	p.AttestationTime(attestation)

	assert.Equal(t, attestation, p.EffectiveTime())
}

func TestAttestationTime(t *testing.T) {
	cases := []struct {
		name                      string
		choosenTime               string
		attestationTime           time.Time
		expectEffectiveTimeUpdate bool
		description               string
	}{
		{
			name:                      "successful attestation time set with AtAttestation choosenTime",
			choosenTime:               AtAttestation,
			attestationTime:           time.Date(2023, 1, 15, 10, 30, 0, 0, time.UTC),
			expectEffectiveTimeUpdate: true,
			description:               "Should set attestation time and update effective time when choosenTime is AtAttestation",
		},
		{
			name:                      "successful attestation time set with Now choosenTime",
			choosenTime:               Now,
			attestationTime:           time.Date(2023, 2, 20, 14, 45, 0, 0, time.UTC),
			expectEffectiveTimeUpdate: false,
			description:               "Should set attestation time but not update effective time when choosenTime is Now",
		},
		{
			name:                      "edge case with zero time attestation",
			choosenTime:               AtAttestation,
			attestationTime:           time.Time{}, // zero time
			expectEffectiveTimeUpdate: true,
			description:               "Should handle zero time correctly and still update effective time when choosenTime is AtAttestation",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Create a policy with the specified choosenTime
			p := &policy{
				choosenTime: c.choosenTime,
			}

			// Store initial effective time for comparison
			initialEffectiveTime := p.effectiveTime

			// Call AttestationTime method
			p.AttestationTime(c.attestationTime)

			// Verify attestation time was set correctly
			assert.NotNil(t, p.attestationTime, "Attestation time should be set")
			assert.Equal(t, c.attestationTime, *p.attestationTime, "Attestation time should match the provided time")

			// Verify effective time behavior
			if c.expectEffectiveTimeUpdate {
				assert.NotNil(t, p.effectiveTime, "Effective time should be updated when choosenTime is AtAttestation")
				assert.Equal(t, c.attestationTime, *p.effectiveTime, "Effective time should match attestation time when choosenTime is AtAttestation")
			} else {
				// Effective time should remain unchanged
				assert.Equal(t, initialEffectiveTime, p.effectiveTime, "Effective time should remain unchanged when choosenTime is not AtAttestation")
			}
		})
	}

	// Additional test for multiple calls to AttestationTime
	t.Run("multiple attestation time calls", func(t *testing.T) {
		p := &policy{
			choosenTime: AtAttestation,
		}

		firstTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
		secondTime := time.Date(2023, 2, 1, 12, 0, 0, 0, time.UTC)

		// First call
		p.AttestationTime(firstTime)
		assert.Equal(t, firstTime, *p.attestationTime, "First attestation time should be set correctly")
		assert.Equal(t, firstTime, *p.effectiveTime, "Effective time should match first attestation time")

		// Second call should override the first
		p.AttestationTime(secondTime)
		assert.Equal(t, secondTime, *p.attestationTime, "Second attestation time should override the first")
		assert.Equal(t, secondTime, *p.effectiveTime, "Effective time should match second attestation time")
	})
}

func toJson(policy any) string {
	newInline, err := json.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid JSON: %w", err))
	}
	return string(newInline)
}

func toYAML(policy any) string {
	inline, err := yaml.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid YAML: %w", err))
	}
	return string(inline)
}

func TestIsConformant(t *testing.T) {
	cases := []struct {
		name       string
		policyRef  string
		expectPass bool
		expectErr  bool
	}{
		{
			name:       "valid policy",
			policyRef:  `{"spec": {"publicKey": "test-key"}}`,
			expectPass: true,
			expectErr:  false,
		},
		{
			name:       "invalid policy",
			policyRef:  `{"spec": {"invalidField": "test"}}`,
			expectPass: false,
			expectErr:  true,
		},
		{
			name:       "invalid YAML",
			policyRef:  `invalid-yaml`,
			expectPass: false,
			expectErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &policy{}
			pass, err := p.isConformant(c.policyRef)

			if c.expectPass {
				assert.True(t, pass, "Expected policy to pass validation")
			} else {
				assert.False(t, pass, "Expected policy to fail validation")
			}

			if c.expectErr {
				assert.Error(t, err, "Expected error during validation")
			} else {
				assert.NoError(t, err, "Expected no error during validation")
			}
		})
	}
}

func TestSigstoreOpts(t *testing.T) {
	cases := []struct {
		name         string
		rekorUrl     string
		ignoreRekor  bool
		publicKey    string
		identity     cosign.Identity
		expectedOpts SigstoreOpts
		err          string
	}{
		{
			name:      "long-lived key with rekor",
			rekorUrl:  utils.TestRekorURL,
			publicKey: utils.TestPublicKey,
			expectedOpts: SigstoreOpts{
				RekorURL:  utils.TestRekorURL,
				PublicKey: utils.TestPublicKey,
			},
		},
		{
			name:        "long-lived key without rekor",
			ignoreRekor: true,
			publicKey:   utils.TestPublicKey,
			expectedOpts: SigstoreOpts{
				IgnoreRekor: true,
				PublicKey:   utils.TestPublicKey,
			},
		},
		{
			name:     "fulcio key with rekor",
			rekorUrl: utils.TestRekorURL,
			identity: cosign.Identity{
				Subject: "my-subject",
				Issuer:  "my-issuer",
			},
			expectedOpts: SigstoreOpts{
				CertificateIdentity:   "my-subject",
				CertificateOIDCIssuer: "my-issuer",
				RekorURL:              utils.TestRekorURL,
			},
		},
		{
			name:        "fulcio key without rekor",
			ignoreRekor: true,
			identity: cosign.Identity{
				Subject: "my-subject",
				Issuer:  "my-issuer",
			},
			expectedOpts: SigstoreOpts{
				CertificateIdentity:   "my-subject",
				CertificateOIDCIssuer: "my-issuer",
				IgnoreRekor:           true,
			},
		},
		{
			name:     "fulcio key with regular expressions",
			rekorUrl: utils.TestRekorURL,
			identity: cosign.Identity{
				SubjectRegExp: "my-subject.*",
				IssuerRegExp:  "my-issuer.*",
			},
			expectedOpts: SigstoreOpts{
				CertificateIdentityRegExp:   "my-subject.*",
				CertificateOIDCIssuerRegExp: "my-issuer.*",
				RekorURL:                    utils.TestRekorURL,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			p, err := NewPolicy(ctx, Options{
				RekorURL:      c.rekorUrl,
				IgnoreRekor:   c.ignoreRekor,
				PublicKey:     c.publicKey,
				EffectiveTime: Now,
				Identity:      c.identity,
			})
			require.NoError(t, err)

			opts, err := p.SigstoreOpts()
			require.NoError(t, err)
			require.Equal(t, opts, c.expectedOpts)
		})
	}
}

func TestUrls(t *testing.T) {
	tests := []struct {
		name string
		s    []source.PolicySource
		kind source.PolicyType
		want []string
	}{
		{
			name: "Returns URLs of the specified kind",
			s: []source.PolicySource{
				&source.PolicyUrl{Url: "http://example.com/policy1", Kind: source.PolicyKind},
				&source.PolicyUrl{Url: "http://example.com/data1", Kind: source.DataKind},
				&source.PolicyUrl{Url: "http://example.com/policy2", Kind: source.PolicyKind},
			},
			kind: source.PolicyKind,
			want: []string{"http://example.com/policy1", "http://example.com/policy2"},
		},
		{
			name: "Returns empty slice when no URLs of the specified kind",
			s: []source.PolicySource{
				&source.PolicyUrl{Url: "http://example.com/data1", Kind: source.PolicyType("data")},
				&source.PolicyUrl{Url: "http://example.com/data2", Kind: source.PolicyType("data")},
			},
			kind: source.PolicyKind,
			want: []string{},
		},
		{
			name: "Returns empty slice when input slice is empty",
			s:    []source.PolicySource{},
			kind: source.PolicyKind,
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := urls(tt.s, tt.kind)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPublicKeyFromKeyRef(t *testing.T) {
	cases := []struct {
		name      string
		publicKey string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid Kubernetes reference",
			publicKey: "k8s://test/cosign-public-key",
			expectErr: false,
		},
		{
			name:      "valid file path reference",
			publicKey: "/path/to/public/key.pem",
			expectErr: false,
		},
		{
			name:      "invalid reference format",
			publicKey: "invalid:format:with:too:many:colons",
			expectErr: true,
			errMsg:    "invalid public key reference format",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			// Use FakeCosignClient to avoid external dependencies
			client := &FakeCosignClient{publicKey: utils.TestPublicKey}

			verifier, err := client.publicKeyFromKeyRef(ctx, c.publicKey)

			if c.expectErr {
				// For invalid references, we expect the FakeCosignClient to return an error
				assert.Error(t, err, "Expected error for invalid public key reference")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, verifier, "Verifier should be nil when error occurs")
			} else {
				// With FakeCosignClient, we should get a successful result for valid references
				assert.NoError(t, err, "Expected no error for valid public key reference")
				assert.NotNil(t, verifier, "Verifier should not be nil for valid public key reference")
			}
		})
	}
}

func TestNewSignatureClient(t *testing.T) {
	cases := []struct {
		name         string
		ctx          context.Context
		expectedType string
		expectNil    bool
		description  string
	}{
		{
			name:         "successful retrieval of existing signature client from context",
			ctx:          withSignatureClient(context.Background(), &FakeCosignClient{publicKey: "test-key"}),
			expectedType: "*policy.FakeCosignClient",
			expectNil:    false,
			description:  "Should return the existing signature client when present in context",
		},
		{
			name:         "successful creation of new cosign client when no client in context",
			ctx:          context.Background(),
			expectedType: "*policy.cosignClient",
			expectNil:    false,
			description:  "Should return a new cosignClient when no signature client exists in context",
		},
		{
			name:         "successful creation of new cosign client when context has nil client",
			ctx:          withSignatureClient(context.Background(), nil),
			expectedType: "*policy.cosignClient",
			expectNil:    false,
			description:  "Should return a new cosignClient when context has nil signature client",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := newSignatureClient(c.ctx)

			if c.expectNil {
				assert.Nil(t, client, "Expected client to be nil")
			} else {
				assert.NotNil(t, client, "Expected client to not be nil")
				assert.Equal(t, c.expectedType, fmt.Sprintf("%T", client), "Expected client type to match")
			}
		})
	}
}

func TestNewInputPolicy(t *testing.T) {
	cases := []struct {
		name          string
		policyRef     string
		effectiveTime string
		expectErr     bool
		errMsg        string
		description   string
	}{
		{
			name:          "valid JSON policy with RFC3339 time",
			policyRef:     `{"publicKey": "test-public-key"}`,
			effectiveTime: "2023-01-01T12:00:00Z",
			expectErr:     false,
			description:   "Should successfully create policy from valid JSON with RFC3339 timestamp",
		},
		{
			name:          "valid YAML policy with date-only time",
			policyRef:     `publicKey: "test-public-key"`,
			effectiveTime: "2023-01-01",
			expectErr:     false,
			description:   "Should successfully create policy from valid YAML with date-only timestamp",
		},
		{
			name:          "invalid effective time format",
			policyRef:     `{"publicKey": "test-public-key"}`,
			effectiveTime: "invalid-time-format",
			expectErr:     true,
			errMsg:        "invalid policy time argument",
			description:   "Should fail when effective time format is invalid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			policy, err := NewInputPolicy(ctx, c.policyRef, c.effectiveTime)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid input")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, policy, "Policy should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for valid input")
				assert.NotNil(t, policy, "Policy should not be nil for successful creation")

				// Verify effective time was parsed correctly
				expectedTime, _ := time.Parse(time.RFC3339, c.effectiveTime)
				if c.effectiveTime == "2023-01-01" {
					expectedTime, _ = time.Parse("2006-01-02", c.effectiveTime)
				}
				assert.Equal(t, expectedTime, policy.EffectiveTime(), "Policy should have correct effective time")

				// Verify the policy implements the Policy interface
				assert.Implements(t, (*Policy)(nil), policy, "Policy should implement the Policy interface")
			}
		})
	}
}

func TestValidateIdentity(t *testing.T) {
	cases := []struct {
		name        string
		identity    cosign.Identity
		expectErr   bool
		errMsg      string
		description string
	}{
		{
			name: "valid identity with issuer and subject",
			identity: cosign.Identity{
				Issuer:  "https://accounts.google.com",
				Subject: "user@example.com",
			},
			expectErr:   false,
			description: "Should pass validation when both issuer and subject are provided",
		},
		{
			name: "valid identity with regexp patterns",
			identity: cosign.Identity{
				IssuerRegExp:  "https://accounts\\.google\\.com",
				SubjectRegExp: ".*@example\\.com",
			},
			expectErr:   false,
			description: "Should pass validation when both issuer and subject regexp patterns are provided",
		},
		{
			name:     "invalid identity missing both issuer and subject",
			identity: cosign.Identity{
				// Both Issuer and Subject are empty
			},
			expectErr:   true,
			errMsg:      "certificate OIDC issuer must be provided for keyless workflow",
			description: "Should fail validation when both issuer and subject are missing",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateIdentity(c.identity)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid identity")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid identity")
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	cases := []struct {
		name         string
		policyConfig string
		expectErr    bool
		errMsg       string
		description  string
	}{
		{
			name: "valid policy configuration with public key",
			policyConfig: `{
				"spec": {
					"publicKey": "test-public-key",
					"rekorUrl": "https://rekor.example.com"
				}
			}`,
			expectErr:   false,
			description: "Should successfully validate policy with public key configuration",
		},
		{
			name: "valid policy configuration with identity",
			policyConfig: `{
				"spec": {
					"identity": {
						"subject": "test-subject",
						"issuer": "test-issuer"
					}
				}
			}`,
			expectErr:   false,
			description: "Should successfully validate policy with identity configuration",
		},
		{
			name: "invalid policy configuration with malformed JSON",
			policyConfig: `{
				"spec": {
					"publicKey": "test-public-key",
					"invalidField": "should not be allowed"
				}
			}`,
			expectErr:   true,
			description: "Should fail validation when policy contains invalid fields",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			err := ValidatePolicy(ctx, c.policyConfig)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid policy configuration")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid policy configuration")
			}
		})
	}
}

// MockDownloader implements the downloaderFunc interface for testing
type MockDownloader struct {
	downloadFunc func(context.Context, string, string, bool) (metadata.Metadata, error)
}

func (m *MockDownloader) Download(ctx context.Context, dest, source string, showMsg bool) (metadata.Metadata, error) {
	if m.downloadFunc != nil {
		return m.downloadFunc(ctx, dest, source, showMsg)
	}
	// Default behavior: return success with a simple metadata
	return &fileMetadata.FSMetadata{
		URI:  source,
		Path: dest,
		Size: 0,
	}, nil
}

func TestPreProcessPolicy(t *testing.T) {
	cases := []struct {
		name          string
		policyOptions Options
		mockDownload  func(context.Context, string, string, bool) (metadata.Metadata, error)
		expectErr     bool
		errMsg        string
		description   string
	}{
		{
			name: "successful preprocessing with simple policy",
			policyOptions: Options{
				PolicyRef:     fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
				EffectiveTime: "2023-01-01T12:00:00Z",
			},
			expectErr:   false,
			description: "Should successfully preprocess a simple policy without sources",
		},
		{
			name: "successful preprocessing with policy containing sources",
			policyOptions: Options{
				PolicyRef: fmt.Sprintf(`{
					"publicKey": %s,
					"sources": [
						{
							"name": "test-source",
							"policy": ["https://example.com/policy1.yaml"],
							"data": ["https://example.com/data1.yaml"]
						}
					]
				}`, utils.TestPublicKeyJSON),
				EffectiveTime: "2023-01-01T12:00:00Z",
			},
			mockDownload: func(ctx context.Context, dest, source string, showMsg bool) (metadata.Metadata, error) {
				// Mock successful download
				return &fileMetadata.FSMetadata{
					URI:  source,
					Path: dest,
					Size: 0,
				}, nil
			},
			expectErr:   false,
			description: "Should successfully preprocess a policy with sources using mocked downloader",
		},
		{
			name: "failed preprocessing with download error",
			policyOptions: Options{
				PolicyRef: fmt.Sprintf(`{
					"publicKey": %s,
					"sources": [
						{
							"name": "test-source",
							"policy": ["https://example.com/policy2.yaml"]
						}
					]
				}`, utils.TestPublicKeyJSON),
				EffectiveTime: "2023-01-01T12:00:00Z",
			},
			mockDownload: func(ctx context.Context, dest, source string, showMsg bool) (metadata.Metadata, error) {
				return nil, fmt.Errorf("network error: connection refused")
			},
			expectErr:   true,
			errMsg:      "network error: connection refused",
			description: "Should fail when downloader returns an error",
		},
		{
			name: "failed preprocessing with invalid policy reference",
			policyOptions: Options{
				PolicyRef:     `{"invalid": "json""}`,
				EffectiveTime: "2023-01-01T12:00:00Z",
			},
			expectErr:   true,
			errMsg:      "unable to parse",
			description: "Should fail when policy reference is invalid JSON",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			// Set up mock downloader if provided
			if c.mockDownload != nil {
				mockDownloader := &MockDownloader{downloadFunc: c.mockDownload}
				ctx = context.WithValue(ctx, source.DownloaderFuncKey, mockDownloader)
			}

			policy, policyCache, err := PreProcessPolicy(ctx, c.policyOptions)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid policy options")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, policy, "Policy should be nil when error occurs")
				assert.Nil(t, policyCache, "Policy cache should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for valid policy options")
				assert.NotNil(t, policy, "Policy should not be nil for successful preprocessing")
				assert.NotNil(t, policyCache, "Policy cache should not be nil for successful preprocessing")

				// Verify the policy implements the Policy interface
				assert.Implements(t, (*Policy)(nil), policy, "Policy should implement the Policy interface")

				// Verify the policy cache is properly initialized
				assert.NotNil(t, &policyCache.Data, "Policy cache data should be initialized")

				// Verify the policy has the expected basic properties
				spec := policy.Spec()
				if strings.Contains(c.policyOptions.PolicyRef, "publicKey") {
					assert.NotEmpty(t, spec.PublicKey, "Policy should have public key when specified")
				}
			}
		})
	}
}

func TestValidatePolicyConfig(t *testing.T) {
	cases := []struct {
		name         string
		policyConfig string
		expectErr    bool
		errMsg       string
		description  string
	}{
		{
			name: "valid policy configuration with public key",
			policyConfig: `{
				"publicKey": "test-public-key",
				"rekorUrl": "https://rekor.example.com"
			}`,
			expectErr:   false,
			description: "Should successfully validate policy with public key configuration",
		},
		{
			name: "valid policy configuration with spec wrapper",
			policyConfig: `{
				"spec": {
					"identity": {
						"subject": "test-subject",
						"issuer": "test-issuer"
					}
				}
			}`,
			expectErr:   false,
			description: "Should successfully validate policy with spec wrapper and identity configuration",
		},
		{
			name: "invalid policy configuration with malformed YAML",
			policyConfig: `{
				"publicKey": "test-public-key",
				"invalidField": "should not be allowed"
			}`,
			expectErr:   true,
			description: "Should fail validation when policy contains invalid fields",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePolicyConfig(c.policyConfig)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid policy configuration")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid policy configuration")
			}
		})
	}
}

func TestWithSignatureClient(t *testing.T) {
	cases := []struct {
		name         string
		client       signatureClient
		expectedType string
		description  string
	}{
		{
			name:         "successful context with FakeCosignClient",
			client:       &FakeCosignClient{publicKey: "test-key"},
			expectedType: "*policy.FakeCosignClient",
			description:  "Should successfully add FakeCosignClient to context",
		},
		{
			name:         "successful context with cosignClient",
			client:       &cosignClient{},
			expectedType: "*policy.cosignClient",
			description:  "Should successfully add cosignClient to context",
		},
		{
			name:         "edge case with nil client",
			client:       nil,
			expectedType: "<nil>",
			description:  "Should handle nil client gracefully",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()

			// Call withSignatureClient to add client to context
			resultCtx := withSignatureClient(ctx, c.client)

			// Verify the context is not nil
			assert.NotNil(t, resultCtx, "Result context should not be nil")

			// Verify the context is different from the original (new context created)
			assert.NotEqual(t, ctx, resultCtx, "Result context should be different from original context")

			// Extract the client from the context to verify it was stored correctly
			storedClient, ok := resultCtx.Value(signatureClientContextKey).(signatureClient)

			if c.client == nil {
				// For nil client, we expect the stored value to be nil
				assert.False(t, ok, "Should not be able to extract nil client as signatureClient")
				assert.Nil(t, storedClient, "Stored client should be nil")
			} else {
				// For non-nil client, we expect it to be stored correctly
				assert.True(t, ok, "Should be able to extract client from context")
				assert.NotNil(t, storedClient, "Stored client should not be nil")
				assert.Equal(t, c.expectedType, fmt.Sprintf("%T", storedClient), "Client type should match expected")

				// Stored client already has type signatureClient, no need for type assertion
			}

			// Verify that the original context is unchanged
			originalClient, ok := ctx.Value(signatureClientContextKey).(signatureClient)
			assert.False(t, ok, "Original context should not contain signature client")
			assert.Nil(t, originalClient, "Original context should not have signature client")
		})
	}
}

func TestSignatureVerifier(t *testing.T) {
	cases := []struct {
		name        string
		publicKey   string
		ctx         context.Context
		expectErr   bool
		errMsg      string
		description string
	}{
		{
			name:        "successful verifier creation with raw public key",
			publicKey:   utils.TestPublicKey,
			ctx:         context.Background(),
			expectErr:   false,
			description: "Should successfully create verifier from raw public key PEM format",
		},
		{
			name:        "successful verifier creation with key reference",
			publicKey:   "k8s://test/cosign-public-key",
			ctx:         withSignatureClient(context.Background(), &FakeCosignClient{publicKey: utils.TestPublicKey}),
			expectErr:   false,
			description: "Should successfully create verifier from key reference using signature client",
		},
		{
			name:        "failed verifier creation with invalid raw public key",
			publicKey:   "-----BEGIN PUBLIC KEY-----\nINVALID_KEY_DATA\n-----END PUBLIC KEY-----",
			ctx:         context.Background(),
			expectErr:   true,
			description: "Should fail when raw public key is invalid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &policy{
				EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
					PublicKey: c.publicKey,
				},
			}

			verifier, err := signatureVerifier(c.ctx, p)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid public key")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, verifier, "Verifier should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for valid public key")
				assert.NotNil(t, verifier, "Verifier should not be nil for successful creation")

				// Verify the verifier has a public key
				pubKey, err := verifier.PublicKey()
				if err == nil {
					assert.NotNil(t, pubKey, "Verifier should have a public key")
				}
			}
		})
	}
}

type FakeCosignClient struct {
	publicKey string
}

func (c *FakeCosignClient) publicKeyFromKeyRef(ctx context.Context, publicKey string) (sigstoreSig.Verifier, error) {
	if strings.Contains(publicKey, "invalid:") {
		return nil, fmt.Errorf("invalid public key reference format")
	}
	return cosignSig.LoadPublicKeyRaw([]byte(c.publicKey), crypto.SHA256)
}
