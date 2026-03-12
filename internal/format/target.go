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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// Target represents a writer with a specified format.
type Target struct {
	Format  string
	Options Options
	writer  io.Writer
}

// options that can be configured per Target
type Options struct {
	ShowSuccesses      bool
	ShowWarnings       bool
	ShowPolicyDocsLink bool
}

// mutate parses the given string as URL query parameters and sets the fields
// according to the parsed values
func (o *Options) mutate(given string) error {
	vals, err := url.ParseQuery(given)
	if err != nil {
		return err
	}

	if v := vals.Get("show-successes"); v != "" {
		if f, err := strconv.ParseBool(v); err == nil {
			o.ShowSuccesses = f
		} else {
			return err
		}
	}

	if v := vals.Get("show-warnings"); v != "" {
		if f, err := strconv.ParseBool(v); err == nil {
			o.ShowWarnings = f
		} else {
			return err
		}
	}

	if v := vals.Get("show-policy-docs-link"); v != "" {
		if f, err := strconv.ParseBool(v); err == nil {
			o.ShowPolicyDocsLink = f
		} else {
			return err
		}
	}

	return nil
}

// Write proxies the write operation to the underlying writer.
func (t *Target) Write(data []byte) (int, error) {
	return t.writer.Write(data)
}

// TargetParser is responsible for creating Target objects.
type TargetParser struct {
	defaultFormat  string
	defaultWriter  io.Writer
	defaultOptions Options
	fs             afero.Fs
}

// NewTargetParser creates a new TargetParser with the given options.
func NewTargetParser(targetName string, options Options, writer io.Writer, fs afero.Fs) TargetParser {
	return TargetParser{defaultFormat: targetName, defaultOptions: options, defaultWriter: writer, fs: fs}
}

// Parse creates a new Target given the provided target name.
func (tm *TargetParser) Parse(given string) (*Target, error) {
	target := Target{writer: tm.defaultWriter}

	formatAndPath, opts, foundOpts := strings.Cut(given, "?")

	target.Options = tm.defaultOptions
	if foundOpts {
		if err := target.Options.mutate(opts); err != nil {
			return nil, err
		}
	}

	var path string
	target.Format, path, _ = strings.Cut(formatAndPath, "=")

	if target.Format == "" {
		target.Format = tm.defaultFormat
	}

	if path != "" {
		target.writer = &fileWriter{path: path, fs: tm.fs}
	}

	return &target, nil
}

// fileWriter implements a simple Writer wrapper for afero.Fs.
type fileWriter struct {
	path string
	fs   afero.Fs
}

func (w fileWriter) Write(data []byte) (int, error) {
	file, err := w.fs.Create(w.path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.Write(data)
}
