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
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/evaluation_target/input"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
)

type Config struct {
	Address            string
	Port               int
	Policy             policy.Policy
	Info               bool
	ShowSuccesses      bool
	ShowWarnings       bool
	ShowPolicyDocsLink bool
}

type Server struct {
	cfg        Config
	evaluators []evaluator.Evaluator
	ready      atomic.Bool
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Start(ctx context.Context) error {
	// The CLI default is "warn" but for the long-running http service we want
	// to use "info" so startup, shutdown, and request details are logged.
	// Don't downgrade if the user already requested a more verbose level using
	// --debug or --verbose.
	if log.GetLevel() < log.InfoLevel {
		log.SetLevel(log.InfoLevel)
	}
	// Beware we're mutating the global logrus logger here, which is should be
	// fine since server mode is a terminal execution path, but would need
	// revisiting if the server was embedded.
	log.SetFormatter(&log.JSONFormatter{})

	log.WithFields(log.Fields{
		"address": s.cfg.Address,
		"port":    s.cfg.Port,
		"sources": len(s.cfg.Policy.Spec().Sources),
	}).Info("Starting server")

	log.Info("Loading policy sources...")
	inp, err := input.NewInput(ctx, nil, s.cfg.Policy)
	if err != nil {
		return fmt.Errorf("loading policy sources: %w", err)
	}
	s.evaluators = inp.Evaluators
	if len(s.evaluators) == 0 {
		return fmt.Errorf("no evaluators created from policy sources, check policy configuration")
	}
	s.ready.Store(true)
	log.Infof("Policy sources loaded, %d evaluator(s) ready", len(s.evaluators))

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	handler := requestLoggingMiddleware(recoveryMiddleware(mux))

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Address, s.cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		ln, err := net.Listen("tcp", httpServer.Addr)
		if err != nil {
			errCh <- fmt.Errorf("listen on %s: %w", httpServer.Addr, err)
			return
		}
		log.Infof("Server listening on %s", ln.Addr())
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		s.destroyEvaluators()
		return err
	case <-ctx.Done():
	}

	log.Info("Shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), evaluationTimeout+5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.WithField("error", err).Warn("Server shutdown error")
	}

	s.destroyEvaluators()
	log.Info("Server stopped")
	return nil
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /live", s.handleLive)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("POST /v1/validate/input", s.handleValidateInput)
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ready"}`)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprint(w, `{"status":"not ready"}`)
}

func (s *Server) destroyEvaluators() {
	for _, e := range s.evaluators {
		e.Destroy()
	}
}
