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

package tekton

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	v1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"sigs.k8s.io/yaml"
)

//go:embed task.tmpl
var tektonTaskTemplateText string

//go:embed nav.tmpl
var tektonNavTemplateText string

var tektonTaskTemplate *template.Template

var tektonNavTemplate *template.Template

var tasks []*v1.Task

func init() {
	tektonTaskTemplate = template.Must(template.New("tekton-task").Funcs(template.FuncMap{
		"replaceAll": strings.ReplaceAll,
	}).Parse(tektonTaskTemplateText))

	tektonNavTemplate = template.Must(template.New("tekton-nav").Parse(tektonNavTemplateText))

	_, __file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to determine the caller")
	}

	matches, err := filepath.Glob(filepath.Join(filepath.Dir(__file), "../../../../tasks/*/*/*.yaml"))
	if err != nil {
		panic(err)
	}

	for _, t := range matches {
		data, err := os.ReadFile(t)
		if err != nil {
			panic(err)
		}

		task := v1.Task{}
		if err := yaml.Unmarshal(data, &task); err != nil {
			panic(err)
		}

		tasks = append(tasks, &task)
	}
}

func GenerateTektonDocumentation(module, marker string) ([]string, error) {
	generated, err := generateTektonReference(module, marker)
	if err != nil {
		return nil, err
	}

	if err := generateTektonNav(module); err != nil {
		return nil, err
	}

	return generated, nil
}

func generateTektonReference(module, marker string) ([]string, error) {
	var generated []string
	for _, task := range tasks {
		docpath := filepath.Join(module, "pages", task.Name+".adoc")
		f, err := os.Create(docpath)
		if err != nil {
			return nil, fmt.Errorf("creating file %q: %w", docpath, err)
		}

		if _, err := fmt.Fprintln(f, marker); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing marker to %q: %w", docpath, err)
		}

		if err := tektonTaskTemplate.Execute(f, task); err != nil {
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

func generateTektonNav(module string) error {
	navpath := filepath.Join(module, "partials", "tasks_nav.adoc")
	f, err := os.Create(navpath)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", navpath, err)
	}
	defer f.Close()

	return tektonNavTemplate.Execute(f, tasks)
}
