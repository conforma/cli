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

// Package log provides per-scenario file-based logging for acceptance tests
package log

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggerWritesToFile(t *testing.T) {
	ctx := context.Background()

	loggerA, _ := LoggerFor(ctx)
	loggerA.Name("ScenarioA")
	defer loggerA.Close()
	defer os.Remove(loggerA.LogFile())

	loggerA.Log("hello from A")
	loggerA.Logf("formatted %s", "message")
	loggerA.Info("info msg")
	loggerA.Warn("warn msg")
	loggerA.Error("error msg")
	loggerA.Close()

	content, err := os.ReadFile(loggerA.LogFile())
	require.NoError(t, err)

	lines := string(content)
	assert.Contains(t, lines, "hello from A")
	assert.Contains(t, lines, "formatted message")
	assert.Contains(t, lines, "[INFO ]")
	assert.Contains(t, lines, "[WARN ]")
	assert.Contains(t, lines, "[ERROR]")
}

func TestLoggerCaching(t *testing.T) {
	ctx := context.Background()

	loggerA, ctx := LoggerFor(ctx)
	defer loggerA.Close()
	defer os.Remove(loggerA.LogFile())

	// Second call with same context returns the cached logger
	loggerB, _ := LoggerFor(ctx)

	assert.Equal(t, loggerA, loggerB)
}

func TestLoggerUniqueness(t *testing.T) {
	ctxA := context.Background()
	ctxB := context.Background()

	loggerA, _ := LoggerFor(ctxA)
	defer loggerA.Close()
	defer os.Remove(loggerA.LogFile())

	loggerB, _ := LoggerFor(ctxB)
	defer loggerB.Close()
	defer os.Remove(loggerB.LogFile())

	assert.NotEqual(t, loggerA.(*logger).id, loggerB.(*logger).id)
	assert.NotEqual(t, loggerA.LogFile(), loggerB.LogFile())
}

func TestLoggerIsolation(t *testing.T) {
	ctxA := context.Background()
	ctxB := context.Background()

	loggerA, _ := LoggerFor(ctxA)
	loggerA.Name("A")
	defer loggerA.Close()
	defer os.Remove(loggerA.LogFile())

	loggerB, _ := LoggerFor(ctxB)
	loggerB.Name("B")
	defer loggerB.Close()
	defer os.Remove(loggerB.LogFile())

	loggerA.Log("only in A")
	loggerB.Log("only in B")

	loggerA.Close()
	loggerB.Close()

	contentA, err := os.ReadFile(loggerA.LogFile())
	require.NoError(t, err)
	contentB, err := os.ReadFile(loggerB.LogFile())
	require.NoError(t, err)

	assert.Contains(t, string(contentA), "only in A")
	assert.NotContains(t, string(contentA), "only in B")
	assert.Contains(t, string(contentB), "only in B")
	assert.NotContains(t, string(contentB), "only in A")
}

func TestLogFileCreatesTemporaryFile(t *testing.T) {
	ctx := context.Background()

	l, _ := LoggerFor(ctx)
	defer l.Close()
	defer os.Remove(l.LogFile())

	path := l.LogFile()
	assert.True(t, strings.Contains(path, "scenario-"))
	assert.True(t, strings.HasSuffix(path, ".log"))

	_, err := os.Stat(path)
	assert.NoError(t, err)
}
