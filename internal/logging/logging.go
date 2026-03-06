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

package logging

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
	log "github.com/sirupsen/logrus"
	"k8s.io/klog/v2"
)

// There are seven log levels supported by logrus but let's not
// expose all that to the user. Instead let's say we have the
// following effective modes of logging: "debug", "verbose",
// "quiet" and "normal" i.e. the default.
//
// "Quiet" shows ErrorLevel messages and higher.
// "Normal" shows WarnLevel messages and higher.
// "Verbose" shows DebugLevel messages and higher.
// And "debug" is the same as Verbose but we add the line
// number and the function name to each log message for extra
// debugging.
//
// We're expecting only one of the bool params to be set, but if
// there are multiple set we'll accept it and the more verbose
// option will take precedence.
func InitLogging(verbose, quiet, debug, trace bool, logfile string) {
	var level log.Level
	var v string
	switch {
	case trace:
		level = log.TraceLevel
		setupDebugMode()
		v = "9"
	case debug:
		level = log.DebugLevel
		setupDebugMode()
		v = "6"
	case verbose:
		level = log.DebugLevel
		v = "6"
	case quiet:
		level = log.ErrorLevel
		v = "1"
	default:
		level = log.WarnLevel
		v = "1"
	}

	log.SetLevel(level)

	// The problem with klog is that it'll log to stdout/stderr, we want to
	// control the logging and log via logrus instead. This accomplishes that
	// but at the cost of loosing log levels, i.e. all klog messages will be
	// logged with the INFO level.
	// see
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md
	// https://github.com/kubernetes/klog/issues/87
	klog.SetLogger(logr.New(&logrusSink{}).V(int(level)))
	flags := &flag.FlagSet{}
	klog.InitFlags(flags)
	if err := flags.Set("v", v); err != nil {
		panic(err)
	}

	if logfile != "" {
		if l, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(l)
		} else {
			fmt.Fprintf(os.Stderr, "Unable to create log file %q, log lines will appear on standard error. Error was: %s\n", logfile, err.Error())
		}
	}
}

func setupDebugMode() {
	// Show the file, line number and function name when logging
	log.SetReportCaller(true)

	// Tweak the output since the defaults are not good
	customTextFormatter := &log.TextFormatter{
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			// The full path is way too long. Extract just the file name.
			shortFile := filepath.Base(f.File)

			// The function name includes the full package which is also way too long.
			// Extract just the function name by itself.
			// (We're abusing filepath.Ext here but I think we can get away with it)
			shortFunction := filepath.Ext(f.Function)[1:]

			// Include the line number as well
			shortFileandLineNumber := fmt.Sprintf(" %s:%d", shortFile, f.Line)

			return shortFunction, shortFileandLineNumber
		},
	}
	log.SetFormatter(customTextFormatter)
}

// logrusSink implements logr.LogSink to pass klog messages to logrus
type logrusSink struct {
	name   string
	fields []any
}

// entry creates a log.Entry with the state (name, fields) passed in as
// fields
func (l logrusSink) entry() *log.Entry {
	e := log.NewEntry(log.StandardLogger())
	if l.name != "" {
		e = e.WithField("name", l.name)
	}
	for i := 0; i < len(l.fields); i += 2 {
		e = e.WithField(fmt.Sprintf("%v", l.fields[i]), l.fields[i+1])
	}

	return e
}

// toLevel converts a logr level to a logrus level, it might as well be replaced
// with a constant returning log.InfoLevel as klog with LogSinks only logs at
// level INFO
func toLevel(level int) log.Level {
	switch level {
	case 0: // severity.InfoLog
		return log.InfoLevel
	case 1: // severity.WarningLog
		return log.WarnLevel
	case 2: // severity.ErrorLog
		return log.ErrorLevel
	case 3: // severity.FatalLog
		return log.FatalLevel
	}

	return log.DebugLevel
}

func (l logrusSink) Init(info logr.RuntimeInfo) {
	// nop
}

func (l logrusSink) Enabled(level int) bool {
	return log.IsLevelEnabled(toLevel(level))
}

func (l logrusSink) Info(level int, msg string, keysAndValues ...interface{}) {
	l.entry().Logf(toLevel(level), msg, keysAndValues...)
}

func (l logrusSink) Error(err error, msg string, keysAndValues ...interface{}) {
	l.entry().WithError(err).Errorf(msg, keysAndValues...)
}

func (l logrusSink) WithValues(fields ...any) logr.LogSink {
	return logrusSink{fields: fields, name: l.name}
}

func (l logrusSink) WithName(name string) logr.LogSink {
	return logrusSink{fields: l.fields, name: name}
}
