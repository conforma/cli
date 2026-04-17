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

// Package log provides per-scenario file-based logging for acceptance tests
package log

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"sigs.k8s.io/kind/pkg/log"
)

type loggerKeyType int

const loggerKey loggerKeyType = 0

var counter atomic.Uint32

// DelegateLogger is the interface used internally to write log output
type DelegateLogger interface {
	Log(args ...any)
	Logf(format string, args ...any)
}

// Logger is the interface used by acceptance test packages for logging
type Logger interface {
	DelegateLogger
	Close()
	Enabled() bool
	Error(message string)
	Errorf(format string, args ...any)
	Info(message string)
	Infof(format string, args ...any)
	LogFile() string
	Name(name string)
	Printf(format string, v ...any)
	V(level log.Level) log.InfoLogger
	Warn(message string)
	Warnf(format string, args ...any)
}

// fileLogger writes log output to a file, one per scenario
type fileLogger struct {
	mu   sync.Mutex
	file *os.File
}

func (f *fileLogger) Log(args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fmt.Fprintln(f.file, args...)
}

func (f *fileLogger) Logf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fmt.Fprintf(f.file, format+"\n", args...)
}

func (f *fileLogger) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file.Close()
}

type logger struct {
	id   uint32
	name string
	t    DelegateLogger
	path string
}

// Log logs given arguments
func (l logger) Log(args ...any) {
	msg := fmt.Sprint(args...)
	l.t.Logf("(%010d: %s) %s", l.id, l.name, msg)
}

// Logf logs using given format and specified arguments
func (l logger) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.t.Logf("(%010d: %s) %s", l.id, l.name, msg)
}

// Printf logs using given format and specified arguments
func (l logger) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.t.Logf("(%010d: %s) %s", l.id, l.name, msg)
}

func (l logger) Warn(message string) {
	l.Logf("[WARN ] %s", message)
}

func (l logger) Warnf(format string, args ...any) {
	l.Logf("[WARN ] %s", fmt.Sprintf(format, args...))
}

func (l logger) Error(message string) {
	l.Logf("[ERROR] %s", message)
}

func (l logger) Errorf(format string, args ...any) {
	l.Logf("[ERROR] %s", fmt.Sprintf(format, args...))
}

func (l logger) Info(message string) {
	l.Logf("[INFO ] %s", message)
}

func (l logger) Infof(format string, args ...any) {
	l.Logf("[INFO ] %s", fmt.Sprintf(format, args...))
}

func (l logger) V(_ log.Level) log.InfoLogger {
	return l
}

func (l logger) Enabled() bool {
	return true
}

func (l *logger) Name(name string) {
	l.name = name
}

// LogFile returns the path to the per-scenario log file
func (l *logger) LogFile() string {
	return l.path
}

// Close closes the underlying log file
func (l *logger) Close() {
	if fl, ok := l.t.(*fileLogger); ok {
		fl.Close()
	}
}

// LoggerFor returns the logger for the provided Context. Each call for
// a new context creates a per-scenario temp file for log isolation.
func LoggerFor(ctx context.Context) (Logger, context.Context) {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger, ctx
	}

	id := counter.Add(1)

	f, err := os.CreateTemp("", fmt.Sprintf("scenario-%010d-*.log", id))
	if err != nil {
		panic(fmt.Sprintf("failed to create scenario log file: %v", err))
	}

	delegate := &fileLogger{file: f}

	logger := logger{
		t:    delegate,
		id:   id,
		name: "*",
		path: f.Name(),
	}

	return &logger, context.WithValue(ctx, loggerKey, &logger)
}
