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
	"net/http"
	"time"
)

var DefaultRetry = Retry{200 * time.Millisecond, 3 * time.Second, 3}

type Retry struct {
	MinWait  time.Duration
	MaxWait  time.Duration
	MaxRetry int
}

// NewRetryTransport creates a custom HTTP transport that handles 429 errors
// with exponential backoff. It wraps the provided transport and adds retry
// logic specifically for rate limiting scenarios.
func NewRetryTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{
		base: base,
	}
}

type retryTransport struct {
	base http.RoundTripper
}

func (r *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt <= DefaultRetry.MaxRetry; attempt++ {
		resp, err := r.base.RoundTrip(req)
		if err != nil {
			lastErr = err
			// Don't retry on network errors, only on HTTP errors
			continue
		}

		// If we get a 429, retry with exponential backoff
		if resp.StatusCode == http.StatusTooManyRequests {
			lastResp = resp
			lastErr = nil

			// Calculate backoff duration
			backoffDuration := calculateBackoff(attempt)

			// Check if we should retry
			if attempt < DefaultRetry.MaxRetry {
				select {
				case <-req.Context().Done():
					return resp, req.Context().Err()
				case <-time.After(backoffDuration):
					continue
				}
			}

			return resp, nil
		}

		// For any other response, return immediately
		return resp, err
	}

	// If we've exhausted all retries, return the last response/error
	if lastResp != nil {
		return lastResp, lastErr
	}

	return nil, lastErr
}

// calculateBackoff calculates the backoff duration for the given attempt.
// It uses exponential backoff with jitter to prevent thundering herd.
func calculateBackoff(attempt int) time.Duration {
	if attempt == 0 {
		return DefaultRetry.MinWait
	}

	// Exponential backoff: base * factor^attempt
	backoff := DefaultBackoff.Duration
	for i := 0; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * DefaultBackoff.Factor)
	}

	// Add jitter to prevent synchronized retries
	jitter := time.Duration(float64(backoff) * DefaultBackoff.Jitter)
	backoff += jitter

	// Cap at maximum wait time
	if backoff > DefaultRetry.MaxWait {
		backoff = DefaultRetry.MaxWait
	}

	return backoff
}
