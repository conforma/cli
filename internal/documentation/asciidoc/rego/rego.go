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

package rego

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/open-policy-agent/opa/v1/ast"

	_ "github.com/conforma/cli/internal/rego"
)

//go:embed rego.tmpl
var regoTemplateText string

//go:embed nav.tmpl
var regoNavTemplateText string

//go:embed builtins.tmpl
var regoBuiltinsTemplateText string

var regoTemplate *template.Template

var regoNavTemplate *template.Template

var regoBuiltinsTemplate *template.Template

var builtins []*ast.Builtin

func init() {
	funcs := template.FuncMap{
		"replaceAll": strings.ReplaceAll,
		"hasPrefix":  strings.HasPrefix,
		"params": func(params ...any) []any {
			return params
		},
		"lvl": func(l int) string {
			return strings.Repeat("*", l)
		},
		"inc": func(l int) int {
			return l + 1
		},
		"seq": func(max int) []int {
			if max == 0 {
				return []int{}
			}

			s := make([]int, max)
			for i := range s {
				s[i] = i
			}

			return s
		},
	}

	regoTemplate = template.Must(template.New("rego").Funcs(funcs).Parse(regoTemplateText))

	regoNavTemplate = template.Must(template.New("rego-nav").Funcs(funcs).Parse(regoNavTemplateText))

	regoBuiltinsTemplate = template.Must(template.New("rego-builtins").Funcs(funcs).Parse(regoBuiltinsTemplateText))

	builtins = findBuiltins()
}

func GenerateRegoReference(module, marker string) ([]string, error) {
	generated, err := generateRegoReference(module, marker)
	if err != nil {
		return nil, err
	}

	if err := generateRegoReferenceNav(module); err != nil {
		return nil, err
	}

	builtinsPath, err := generateRegoBuiltins(module, marker)
	if err != nil {
		return nil, err
	}
	generated = append(generated, builtinsPath)

	return generated, nil
}

func findBuiltins() []*ast.Builtin {
	builtins := make([]*ast.Builtin, 0, 15)
	for n, b := range ast.BuiltinMap {
		if strings.HasPrefix(n, "ec.") {
			builtins = append(builtins, b)
		}
	}

	sort.Slice(builtins, func(i, j int) bool {
		return builtins[i].Name < builtins[j].Name
	})

	return builtins
}

func generateRegoReference(module, marker string) ([]string, error) {
	var generated []string
	for _, b := range builtins {
		docpath := filepath.Join(module, "pages", strings.ReplaceAll(b.Name, ".", "_")+".adoc")
		f, err := os.Create(docpath)
		if err != nil {
			return nil, fmt.Errorf("creating file %q: %w", docpath, err)
		}

		if _, err := fmt.Fprintln(f, marker); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing marker to %q: %w", docpath, err)
		}

		if err := regoTemplate.Execute(f, b); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("closing file %q: %w", docpath, err)
		}
		generated = append(generated, docpath)
	}

	return generated, nil
}

func generateRegoReferenceNav(module string) error {
	navpath := filepath.Join(module, "partials", "rego_nav.adoc")
	f, err := os.Create(navpath)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", navpath, err)
	}
	defer f.Close()

	return regoNavTemplate.Execute(f, builtins)
}

func generateRegoBuiltins(module, marker string) (string, error) {
	builtinsPath := filepath.Join(module, "pages", "rego_builtins.adoc")
	f, err := os.Create(builtinsPath)
	if err != nil {
		return "", fmt.Errorf("creating file %q: %w", builtinsPath, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, marker); err != nil {
		return "", fmt.Errorf("writing marker to %q: %w", builtinsPath, err)
	}

	return builtinsPath, regoBuiltinsTemplate.Execute(f, builtins)
}
