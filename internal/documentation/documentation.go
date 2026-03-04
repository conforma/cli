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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra/doc"

	cmd "github.com/conforma/cli/cmd"
	"github.com/conforma/cli/cmd/test"
	"github.com/conforma/cli/internal/documentation/asciidoc"
)

const DirectoryPermissions = 0o755

var (
	man  = flag.String("man", "", "Location of the generated Man files")
	adoc = flag.String("adoc", "", "Location of the generated Asciidoc files")
)

func init() {
	c := cmd.RootCmd
	c.AddCommand(test.NewTestCommand(c.Context()))
}

func main() {
	// opa run is using $HOME for the --history flag, $HOME is environment
	// specific, so to reduce the differences we set the HOME to `$HOME` to
	// eliminate the environment difference
	if os.Getenv("HOME") != "$HOME" {
		exe, err := os.Executable()
		if err != nil {
			panic(err)
		}

		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = append(cmd.Env, "HOME=$HOME")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		os.Exit(cmd.ProcessState.ExitCode())
	}

	flag.Parse()

	// Disable generated tags
	cmd.RootCmd.DisableAutoGenTag = true

	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	// Man pages
	if *man != "" {
		if err = os.MkdirAll(*man, DirectoryPermissions); err != nil {
			return
		}
		if err = doc.GenManTree(cmd.RootCmd, nil, *man); err != nil {
			return
		}
	}

	if *adoc != "" {
		if err = os.MkdirAll(*adoc, DirectoryPermissions); err != nil {
			return
		}
		if err = asciidoc.GenerateAsciidoc(*adoc); err != nil {
			return
		}
	}
}
