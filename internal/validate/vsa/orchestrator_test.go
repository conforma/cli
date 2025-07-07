// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package vsa

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock implementations for testing

type mockPredicateGenerator struct {
	GeneratePredicateFunc func(ctx context.Context) (*Predicate, error)
}

func (m *mockPredicateGenerator) GeneratePredicate(ctx context.Context) (*Predicate, error) {
	return m.GeneratePredicateFunc(ctx)
}

type mockPredicateWriter struct {
	WritePredicateFunc func(pred *Predicate) (string, error)
}

func (m *mockPredicateWriter) WritePredicate(pred *Predicate) (string, error) {
	return m.WritePredicateFunc(pred)
}

type mockPredicateAttestor struct {
	AttestPredicateFunc func(ctx context.Context) ([]byte, error)
	WriteEnvelopeFunc   func(data []byte) (string, error)
	TargetDigestFunc    func() string
}

func (m *mockPredicateAttestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	return m.AttestPredicateFunc(ctx)
}

func (m *mockPredicateAttestor) WriteEnvelope(data []byte) (string, error) {
	return m.WriteEnvelopeFunc(data)
}

func (m *mockPredicateAttestor) TargetDigest() string {
	return m.TargetDigestFunc()
}

// Tests for standalone functions

func TestGenerateAndWriteVSA_Success(t *testing.T) {
	ctx := context.Background()
	pred := &Predicate{ImageRef: "test-image"}

	gen := &mockPredicateGenerator{
		GeneratePredicateFunc: func(ctx context.Context) (*Predicate, error) {
			return pred, nil
		},
	}
	writer := &mockPredicateWriter{
		WritePredicateFunc: func(p *Predicate) (string, error) {
			if p != pred {
				t.Errorf("unexpected predicate passed to WritePredicate")
			}
			return "/tmp/vsa.json", nil
		},
	}

	path, err := GenerateAndWriteVSA(ctx, gen, writer)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/vsa.json", path)
}

func TestGenerateAndWriteVSA_Errors(t *testing.T) {
	ctx := context.Background()
	pred := &Predicate{ImageRef: "test-image"}

	t.Run("predicate generation fails", func(t *testing.T) {
		gen := &mockPredicateGenerator{
			GeneratePredicateFunc: func(ctx context.Context) (*Predicate, error) {
				return nil, errors.New("predicate generation error")
			},
		}
		writer := &mockPredicateWriter{}

		path, err := GenerateAndWriteVSA(ctx, gen, writer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "predicate generation error")
		assert.Empty(t, path)
	})

	t.Run("write VSA fails", func(t *testing.T) {
		gen := &mockPredicateGenerator{
			GeneratePredicateFunc: func(ctx context.Context) (*Predicate, error) {
				return pred, nil
			},
		}
		writer := &mockPredicateWriter{
			WritePredicateFunc: func(p *Predicate) (string, error) {
				return "", errors.New("write VSA error")
			},
		}

		path, err := GenerateAndWriteVSA(ctx, gen, writer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write VSA error")
		assert.Empty(t, path)
	})
}

func TestAttestVSA_Success(t *testing.T) {
	ctx := context.Background()

	attestor := &mockPredicateAttestor{
		AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
			return []byte("envelope data"), nil
		},
		WriteEnvelopeFunc: func(data []byte) (string, error) {
			assert.Equal(t, []byte("envelope data"), data)
			return "/tmp/envelope.jsonl", nil
		},
		TargetDigestFunc: func() string {
			return "sha256:testdigest"
		},
	}

	path, err := AttestVSA(ctx, attestor)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/envelope.jsonl", path)
}

func TestAttestVSA_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("attest predicate fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return nil, errors.New("attest predicate error")
			},
			TargetDigestFunc: func() string {
				return "sha256:testdigest"
			},
		}

		path, err := AttestVSA(ctx, attestor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attest predicate error")
		assert.Contains(t, err.Error(), "sha256:testdigest")
		assert.Empty(t, path)
	})

	t.Run("write envelope fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return []byte("envelope data"), nil
			},
			WriteEnvelopeFunc: func(data []byte) (string, error) {
				return "", errors.New("write envelope error")
			},
			TargetDigestFunc: func() string {
				return "sha256:testdigest"
			},
		}

		path, err := AttestVSA(ctx, attestor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write envelope error")
		assert.Contains(t, err.Error(), "sha256:testdigest")
		assert.Empty(t, path)
	})
}
