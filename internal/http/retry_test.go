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

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRetryTransport(t *testing.T) {
	// Test that NewRetryTransport returns a transport
	transport := NewRetryTransport(nil)
	assert.NotNil(t, transport)

	// Test that it wraps the base transport correctly
	baseTransport := &http.Transport{}
	retryTransport := NewRetryTransport(baseTransport)
	assert.NotNil(t, retryTransport)
}

func TestRetryTransport_429Retry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, err := w.Write([]byte(`{"error": "Too Many Requests"}`))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"success": true}`))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create a transport that will retry on 429 with shorter timeouts for testing
	baseTransport := &http.Transport{}

	// Temporarily override the default retry settings for this test
	originalRetry := DefaultRetry
	DefaultRetry = Retry{10 * time.Millisecond, 100 * time.Millisecond, 3}
	defer func() { DefaultRetry = originalRetry }()

	retryTransport := NewRetryTransport(baseTransport)

	// Create a request
	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Execute the request
	start := time.Now()
	resp, err := retryTransport.RoundTrip(req)
	duration := time.Since(start)

	// Verify the response
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify that we retried (should have called the server 3 times)
	assert.Equal(t, 3, callCount)

	// Verify that we waited between retries (should be at least the minimum wait time)
	assert.GreaterOrEqual(t, duration, 10*time.Millisecond)
}

func TestRetryTransport_NoRetryOnOtherErrors(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusForbidden)
		_, err := w.Write([]byte(`{"error": "Forbidden"}`))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create a transport that will retry on 429
	baseTransport := &http.Transport{}
	retryTransport := NewRetryTransport(baseTransport)

	// Create a request
	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Execute the request
	resp, err := retryTransport.RoundTrip(req)

	// Verify the response
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Verify that we didn't retry (should have called the server only once)
	assert.Equal(t, 1, callCount)
}

func TestRetryTransport_ContextCancellation(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusTooManyRequests)
		_, err := w.Write([]byte(`{"error": "Too Many Requests"}`))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create a transport that will retry on 429
	baseTransport := &http.Transport{}
	retryTransport := NewRetryTransport(baseTransport)

	// Create a request with a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	require.NoError(t, err)

	// Cancel the context immediately
	cancel()

	// Execute the request
	resp, err := retryTransport.RoundTrip(req)

	// Verify that we got a context cancellation error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
	assert.Nil(t, resp)

	// Verify that we didn't retry much (context was cancelled)
	assert.LessOrEqual(t, callCount, 1)
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name     string
		attempt  int
		minValue time.Duration
		maxValue time.Duration
	}{
		{
			name:     "first attempt",
			attempt:  0,
			minValue: DefaultRetry.MinWait,
			maxValue: DefaultRetry.MinWait,
		},
		{
			name:     "second attempt",
			attempt:  1,
			minValue: time.Duration(float64(DefaultBackoff.Duration) * DefaultBackoff.Factor),
			maxValue: DefaultRetry.MaxWait,
		},
		{
			name:     "third attempt",
			attempt:  2,
			minValue: time.Duration(float64(DefaultBackoff.Duration) * DefaultBackoff.Factor * DefaultBackoff.Factor),
			maxValue: DefaultRetry.MaxWait,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := calculateBackoff(tt.attempt)

			// For the first attempt, it should be exactly the minimum wait time
			if tt.attempt == 0 {
				assert.Equal(t, DefaultRetry.MinWait, backoff)
			} else {
				// For subsequent attempts, check that it's within the expected range
				// The actual value will be capped at MaxWait and include jitter
				assert.LessOrEqual(t, backoff, tt.maxValue)

				// For attempts that don't exceed MaxWait, check minimum
				if tt.minValue <= tt.maxValue {
					assert.GreaterOrEqual(t, backoff, tt.minValue)
				}
			}
		})
	}
}

func TestRetryConfig(t *testing.T) {
	// Test default configuration
	config := GetRetryConfig()
	assert.Equal(t, 200*time.Millisecond, config.MinWait)
	assert.Equal(t, 3*time.Second, config.MaxWait)
	assert.Equal(t, 3, config.MaxRetry)
	assert.Equal(t, 1*time.Second, config.Duration)
	assert.Equal(t, 2.0, config.Factor)
	assert.Equal(t, 0.1, config.Jitter)

	// Test setting custom configuration
	customConfig := RetryConfig{
		MinWait:  100 * time.Millisecond,
		MaxWait:  2 * time.Second,
		MaxRetry: 5,
		Duration: 500 * time.Millisecond,
		Factor:   1.5,
		Jitter:   0.2,
	}
	SetRetryConfig(customConfig)

	// Verify the configuration was applied
	updatedConfig := GetRetryConfig()
	assert.Equal(t, customConfig.MinWait, updatedConfig.MinWait)
	assert.Equal(t, customConfig.MaxWait, updatedConfig.MaxWait)
	assert.Equal(t, customConfig.MaxRetry, updatedConfig.MaxRetry)
	assert.Equal(t, customConfig.Duration, updatedConfig.Duration)
	assert.Equal(t, customConfig.Factor, updatedConfig.Factor)
	assert.Equal(t, customConfig.Jitter, updatedConfig.Jitter)

	// Test that the backoff calculation uses the new configuration
	backoff := calculateBackoff(1)
	expectedBackoff := time.Duration(float64(customConfig.Duration) * customConfig.Factor)
	assert.GreaterOrEqual(t, backoff, expectedBackoff)
	assert.LessOrEqual(t, backoff, expectedBackoff+time.Duration(float64(expectedBackoff)*customConfig.Jitter))
}

func TestRetryTransport_WithCustomConfig(t *testing.T) {
	// Set custom retry configuration
	customConfig := RetryConfig{
		MinWait:  50 * time.Millisecond,  // Much shorter for testing
		MaxWait:  200 * time.Millisecond, // Much shorter for testing
		MaxRetry: 2,
		Duration: 25 * time.Millisecond, // Much shorter for testing
		Factor:   2.0,
		Jitter:   0.1,
	}
	SetRetryConfig(customConfig)
	defer func() {
		// Restore default configuration
		SetRetryConfig(RetryConfig{
			MinWait:  200 * time.Millisecond,
			MaxWait:  3 * time.Second,
			MaxRetry: 3,
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
		})
	}()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, err := w.Write([]byte(`{"error": "Too Many Requests"}`))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"success": true}`))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create a transport that will retry on 429 with custom configuration
	baseTransport := &http.Transport{}
	retryTransport := NewRetryTransport(baseTransport)

	// Create a request
	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Execute the request
	start := time.Now()
	resp, err := retryTransport.RoundTrip(req)
	duration := time.Since(start)

	// Verify the response
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify that we retried (should have called the server 3 times)
	assert.Equal(t, 3, callCount)

	// Verify that we waited between retries (should be at least the minimum wait time)
	assert.GreaterOrEqual(t, duration, customConfig.MinWait)
}
