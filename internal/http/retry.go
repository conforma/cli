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

package http

import (
	"crypto/rand"
	"math"
	"math/big"
	"net/http"
	"time"
)

var DefaultRetry = Retry{3 * time.Second, 3}

// RetryConfig holds the configuration for retry behavior
type RetryConfig struct {
	MaxWait  time.Duration
	MaxRetry int
	Duration time.Duration
	Factor   float64
	Jitter   float64
}

// GetRetryConfig returns the current retry configuration
func GetRetryConfig() RetryConfig {
	return RetryConfig{
		MaxWait:  DefaultRetry.MaxWait,
		MaxRetry: DefaultRetry.MaxRetry,
		Duration: DefaultBackoff.Duration,
		Factor:   DefaultBackoff.Factor,
		Jitter:   DefaultBackoff.Jitter,
	}
}

// SetRetryConfig updates the retry configuration
func SetRetryConfig(config RetryConfig) {
	DefaultRetry = Retry{
		MaxWait:  config.MaxWait,
		MaxRetry: config.MaxRetry,
	}
	DefaultBackoff = Backoff{
		Duration: config.Duration,
		Factor:   config.Factor,
		Jitter:   config.Jitter,
	}
}

type Retry struct {
	MaxWait  time.Duration
	MaxRetry int
}

type retryTransport struct {
	base    http.RoundTripper
	retry   Retry
	backoff Backoff
}

// NewRetryTransport creates a custom HTTP transport that handles 429, 408, and 503 errors
// with exponential backoff. It wraps the provided transport and adds retry
// logic specifically for rate limiting, timeout, and service unavailable scenarios.
func NewRetryTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{
		base:    base,
		retry:   DefaultRetry,
		backoff: DefaultBackoff,
	}
}

// NewRetryTransportWithConfig creates a retry transport with custom retry and backoff settings
func NewRetryTransportWithConfig(base http.RoundTripper, retry Retry, backoff Backoff) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{
		base:    base,
		retry:   retry,
		backoff: backoff,
	}
}

func (r *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt <= r.retry.MaxRetry; attempt++ {
		resp, err := r.base.RoundTrip(req)
		if err != nil {
			lastErr = err
			// Don't retry on network errors, only on HTTP errors
			continue
		}

		// If we get a 429, 408, or 503, retry with exponential backoff
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusServiceUnavailable {
			lastResp = resp
			lastErr = nil

			// Calculate backoff duration
			backoff := r.calculateBackoff(attempt)

			// Check if context is cancelled
			select {
			case <-req.Context().Done():
				return resp, req.Context().Err()
			case <-time.After(backoff):
				// Continue to next attempt
			}

			continue
		}

		// For any other status code, return immediately
		return resp, nil
	}

	// If we've exhausted all retries, return the last response/error
	if lastResp != nil {
		return lastResp, lastErr
	}
	return nil, lastErr
}

// calculateBackoff computes the exponential backoff duration with jitter
func (r *retryTransport) calculateBackoff(attempt int) time.Duration {
	if attempt == 0 {
		// First attempt uses the base duration
		return r.backoff.Duration
	}

	// Calculate exponential backoff starting from the base duration
	duration := time.Duration(float64(r.backoff.Duration) * math.Pow(r.backoff.Factor, float64(attempt)))

	// Add jitter to prevent thundering herd
	if r.backoff.Jitter > 0 {
		jitter := float64(duration) * r.backoff.Jitter
		// Generate random number between -1 and 1
		randomBytes := make([]byte, 8)
		_, err := rand.Read(randomBytes)
		if err == nil {
			// Convert to float64 and scale to -1 to 1
			randomInt := new(big.Int).SetBytes(randomBytes)
			randomFloat := new(big.Float).SetInt(randomInt)
			randomFloat.Quo(randomFloat, new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 63)))
			randomValue, _ := randomFloat.Float64()
			randomValue = randomValue*2 - 1 // Scale to -1 to 1
			duration += time.Duration(jitter * randomValue)
		}
	}

	// Cap at maximum wait time
	if duration > r.retry.MaxWait {
		duration = r.retry.MaxWait
	}

	return duration
}
