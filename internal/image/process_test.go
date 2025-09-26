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

package image

import (
	"context"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
)

var testHash = v1.Hash{
	Algorithm: "sha256",
	Hex:       "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
}

// func ParseAndResolveAll(urls []string) ([]ImageReference, error) {
func TestParseAndResolveAll(t *testing.T) {
	tests := []struct {
		name       string
		urls       []string
		refs       []ImageReference
		err        string
		headDigest v1.Hash
		opts       []name.Option
	}{
		{
			name: "url contains tag and digest",
			urls: []string{
				"registry.com/repo:one@" + testHash.String(),
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "one",
				},
			},
		},
		{
			name: "url contains only tag",
			urls: []string{
				"registry.com/repo:one",
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "one",
				},
			},
			headDigest: testHash,
		},
		{
			name: "url contains only digest",
			urls: []string{
				"registry.com/repo@" + testHash.String(),
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "latest",
				},
			},
		},
		{
			name: "errors are collected for each url",
			urls: []string{
				// Incomplete digest
				"registry.com/one@sha256:123",
				// Bad registry host
				"registry/two@" + testHash.String(),
				// Missing repo
				"three.com@" + testHash.String(),
				// But this one should cause no errors
				"registry.com/repo:good@" + testHash.String(),
			},
			opts: []name.Option{name.StrictValidation},
			err: `could not parse reference: registry.com/one@sha256:123
could not parse reference: registry/two@` + testHash.String() + `
could not parse reference: three.com@` + testHash.String(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remoteHead := func(ref name.Reference, options ...remote.Option) (*v1.Descriptor, error) {
				// Ensure it is only called when expected.
				assert.NotEmpty(t, tt.headDigest)
				return &v1.Descriptor{Digest: tt.headDigest}, nil
			}
			ctx := context.WithValue(context.Background(), RemoteHead, remoteHead)

			refs, err := ParseAndResolveAll(ctx, tt.urls, tt.opts...)
			if tt.err != "" {
				assert.ErrorContains(t, err, tt.err)
				return
			}
			assert.NoError(t, err)
			// Ignore exact match of the internal state
			for i := 0; i < len(refs); i++ {
				refs[i].ref = nil
			}
			assert.Equal(t, tt.refs, refs)
		})
	}
}

func TestImageReferenceString(t *testing.T) {
	cases := []struct {
		name     string
		ref      ImageReference
		expected string
	}{
		{
			name: "repository only",
			ref: ImageReference{
				Repository: "repository.com/repo",
			},
			expected: "repository.com/repo",
		},
		{
			name: "digest only",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Digest:     testHash.String(),
			},
			expected: "repository.com/repo@" + testHash.String(),
		},
		{
			name: "tag only",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Tag:        "1.0",
			},
			expected: "repository.com/repo:1.0",
		},
		{
			name: "both digest and tag",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Digest:     testHash.String(),
				Tag:        "1.0",
			},
			expected: "repository.com/repo:1.0@" + testHash.String(),
		},
	}

	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, c.expected, c.ref.String())
		})
	}
}

func TestImageReferenceRef(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		opts        []name.Option
		expectError bool
		errorMsg    string
	}{
		{
			name: "repository with tag",
			url:  "registry.com/repo:v1.0.0",
		},
		{
			name: "repository with digest",
			url:  "registry.com/repo@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
		},
		{
			name: "repository with tag and digest",
			url:  "registry.com/repo:v1.0.0@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
		},
		{
			name: "repository only (defaults to latest)",
			url:  "registry.com/repo",
		},
		{
			name: "docker.io registry",
			url:  "docker.io/library/ubuntu:20.04",
		},
		{
			name: "localhost registry",
			url:  "localhost:5000/test/image:latest",
		},
		{
			name: "gcr.io registry",
			url:  "gcr.io/project/image:tag",
		},
		{
			name:        "invalid URL - empty string",
			url:         "",
			expectError: true,
			errorMsg:    "could not parse reference",
		},
		{
			name:        "invalid URL - malformed",
			url:         "invalid::reference",
			expectError: true,
			errorMsg:    "could not parse reference",
		},
		{
			name:        "invalid URL - invalid digest",
			url:         "registry.com/repo@sha256:invalid",
			opts:        []name.Option{name.StrictValidation},
			expectError: true,
			errorMsg:    "could not parse reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create ImageReference using NewImageReference
			imageRef, err := NewImageReference(tt.url, tt.opts...)

			if tt.expectError {
				assert.Error(t, err, "NewImageReference should return error for invalid URL")
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
				}
				return
			}

			assert.NoError(t, err, "NewImageReference should not return error for valid URL")
			assert.NotNil(t, imageRef, "ImageReference should not be nil")

			// Test the Ref() method
			ref := imageRef.Ref()

			// Verify that Ref() returns a non-nil name.Reference
			assert.NotNil(t, ref, "Ref() should not return nil")

			// Verify that the returned reference string matches the original URL format
			// (accounting for normalization that the parsing library might do)
			refString := ref.String()
			assert.NotEmpty(t, refString, "Ref().String() should not be empty")

			// Verify the returned reference is consistent with the ImageReference data
			switch r := ref.(type) {
			case name.Tag:
				assert.NotEmpty(t, imageRef.Tag, "ImageReference should have tag when Ref() returns name.Tag")
				assert.Equal(t, imageRef.Repository, r.Repository.Name(), "Repository should match")
				assert.Equal(t, imageRef.Tag, r.TagStr(), "Tag should match")
			case name.Digest:
				assert.NotEmpty(t, imageRef.Digest, "ImageReference should have digest when Ref() returns name.Digest")
				assert.Equal(t, imageRef.Repository, r.Repository.Name(), "Repository should match")
				assert.Equal(t, imageRef.Digest, r.DigestStr(), "Digest should match")
			}

			// Verify that calling Ref() multiple times returns the same reference
			ref2 := imageRef.Ref()
			assert.Equal(t, ref, ref2, "Multiple calls to Ref() should return the same reference")

			// Verify that the reference can be converted back to a string
			assert.NotPanics(t, func() {
				_ = ref.String()
			}, "Ref().String() should not panic")
		})
	}
}
