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

package server

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type contextKey int

const loggerKey contextKey = iota

func requestLogger(ctx context.Context) *log.Entry {
	if l, ok := ctx.Value(loggerKey).(*log.Entry); ok {
		return l
	}
	return log.NewEntry(log.StandardLogger())
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
}

func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sc := &statusCapture{ResponseWriter: w, status: http.StatusOK}

		logger := log.WithFields(log.Fields{
			"request_id": uuid.New().String(),
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
		})
		ctx := context.WithValue(r.Context(), loggerKey, logger)
		r = r.WithContext(ctx)

		next.ServeHTTP(sc, r)

		logger.WithFields(log.Fields{
			"status":  sc.status,
			"latency": time.Since(start).String(),
			"size":    r.ContentLength,
		}).Info("Request completed")
	})
}
