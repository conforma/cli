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

package mocks

import (
	"bytes"
	"io"
	"net/http"
)

type HttpTransportMockSuccess struct{}
type HttpTransportMockFailure struct{}
type HttpTransportTimeoutFailure struct {
	CallCount int
}
type HttpTransportTooManyRequestsFailure struct {
	CallCount int
}

func (h *HttpTransportMockSuccess) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":          {"application/json"},
			"Docker-Content-Digest": {"sha256:11db66166c3d16c8251134e538b794ec08dfbe5f11bcc8066c6fe50e3282d6ed"},
		},
	}, nil
}

func (h *HttpTransportMockFailure) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 403,
		Header: http.Header{
			"Content-Type":          {"application/json"},
			"Docker-Content-Digest": {"sha256:11db66166c3d16c8251134e538b794ec08dfbe5f11bcc8066c6fe50e3282d6ed"},
		},
	}, nil
}

func (h *HttpTransportTimeoutFailure) RoundTrip(req *http.Request) (*http.Response, error) {
	h.CallCount++
	if h.CallCount <= 2 {
		return &http.Response{
			StatusCode: http.StatusRequestTimeout,
			Body:       io.NopCloser(bytes.NewBufferString(`{"error": "Gateway Timeout"}`)),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":          {"application/json"},
			"Docker-Content-Digest": {"sha256:11db66166c3d16c8251134e538b794ec08dfbe5f11bcc8066c6fe50e3282d6ed"},
		},
	}, nil
}

func (h *HttpTransportTooManyRequestsFailure) RoundTrip(req *http.Request) (*http.Response, error) {
	h.CallCount++
	if h.CallCount <= 2 {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       io.NopCloser(bytes.NewBufferString(`{"error": "Too Many Requests"}`)),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":          {"application/json"},
			"Docker-Content-Digest": {"sha256:11db66166c3d16c8251134e538b794ec08dfbe5f11bcc8066c6fe50e3282d6ed"},
		},
	}, nil
}
