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
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/input"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/utils"
)

const MaxRequestBodySize = 80 << 20 // 80 MB

const EvaluationTimeout = 90 * time.Second

var evaluationTimeout = EvaluationTimeout

type errorResponse struct {
	Error  string `json:"error"`
	Status int    `json:"status"`
}

func (s *Server) handleValidateInput(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := requestLogger(ctx)

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize+1))
	if err != nil {
		logger.WithField("error", err).Error("Failed to read request body")
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "request body is empty")
		return
	}
	if len(body) > MaxRequestBodySize {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %dMB limit", MaxRequestBodySize>>20))
		return
	}

	if !isValidInput(r, body) {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON or YAML")
		return
	}

	tmpFile, err := os.CreateTemp("", "ec-server-input-*"+inputExtension(r, body))
	if err != nil {
		logger.WithField("error", err).Error("Failed to create temp file")
		writeError(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(body); err != nil {
		tmpFile.Close()
		logger.WithField("error", err).Error("Failed to write temp file")
		writeError(w, http.StatusInternalServerError, "failed to write temp file")
		return
	}
	tmpFile.Close()

	data, success, err := s.evaluateAndBuildReport(ctx, tmpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := "fail"
	if success {
		result = "pass"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Conforma-Result", result)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) evaluateAndBuildReport(ctx context.Context, inputPath string) ([]byte, bool, error) {
	logger := requestLogger(ctx)

	evalCtx, evalCancel := context.WithTimeout(ctx, evaluationTimeout)
	defer evalCancel()

	var allResults []evaluator.Outcome
	for _, e := range s.evaluators {
		results, err := e.Evaluate(evalCtx, evaluator.EvaluationTarget{Inputs: []string{inputPath}})
		if err != nil {
			logger.WithField("error", err).Error("Evaluation failed")
			msg := "evaluation failed"
			if evalCtx.Err() == context.DeadlineExceeded {
				msg = "evaluation timed out"
			}
			return nil, false, fmt.Errorf("%s", msg)
		}
		allResults = append(allResults, results...)
	}

	out := output.Output{Detailed: s.cfg.Info}
	out.SetPolicyCheck(allResults)

	inp := input.Input{
		FilePath: "input",
		Success:  true,
	}

	inp.Violations = out.Violations()

	warnings := out.Warnings()
	if s.cfg.ShowWarnings {
		inp.Warnings = warnings
	}

	successes := out.Successes()
	inp.SuccessCount = len(successes)
	if s.cfg.ShowSuccesses {
		inp.Successes = successes
	}
	inp.Success = len(inp.Violations) == 0

	report, err := input.NewReport(
		[]input.Input{inp},
		s.cfg.Policy,
		[][]byte{out.PolicyInput},
		s.cfg.ShowSuccesses,
		s.cfg.ShowWarnings,
		s.cfg.ShowPolicyDocsLink,
	)
	if err != nil {
		logger.WithField("error", err).Error("Failed to build report")
		return nil, false, fmt.Errorf("failed to build report")
	}

	data, err := json.Marshal(report)
	if err != nil {
		logger.WithField("error", err).Error("Failed to marshal report")
		return nil, false, fmt.Errorf("failed to marshal report")
	}

	return data, inp.Success, nil
}

func mediaType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return ""
	}
	mt, _, _ := mime.ParseMediaType(ct)
	return mt
}

func inputExtension(r *http.Request, body []byte) string {
	switch mediaType(r) {
	case "application/json":
		return ".json"
	case "application/yaml", "application/x-yaml", "text/yaml":
		return ".yaml"
	default:
		if utils.IsJson(string(body)) {
			return ".json"
		}
		return ".yaml"
	}
}

func isValidInput(r *http.Request, body []byte) bool {
	switch mediaType(r) {
	case "application/json":
		return utils.IsJson(string(body))
	case "application/yaml", "application/x-yaml", "text/yaml":
		return utils.IsYamlMap(string(body))
	default:
		return utils.IsJson(string(body)) || utils.IsYamlMap(string(body))
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message, Status: status})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.WithFields(log.Fields{"panic": rec, "stack": string(debug.Stack())}).Error("Recovered from panic in handler")
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
