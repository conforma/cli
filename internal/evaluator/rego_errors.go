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

package evaluator

import (
	"fmt"
	dbg "runtime/debug"
	"strings"
)

// opaModulePath is the Go module path used to look up the bundled OPA version
// from build info.
const opaModulePath = "github.com/open-policy-agent/opa"

// disallowedBuiltins lists the OPA built-in functions that are disabled by
// strictCapabilities for security reasons. This is the single source of truth
// used by both strictCapabilities (conftest_evaluator.go) and wrapRegoError.
var disallowedBuiltins = []string{
	"opa.runtime",
	"http.send",
	"net.lookup_ip_addr",
}

// readBuildInfo is a variable to allow overriding in tests.

var readBuildInfo = dbg.ReadBuildInfo

// isRegoCompilationError checks whether the error message contains OPA/Rego
// compilation error patterns (rego_type_error, rego_parse_error,
// rego_compile_error) that may indicate a version incompatibility or a
// capability restriction.
func isRegoCompilationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "rego_type_error") ||
		strings.Contains(msg, "rego_parse_error") ||
		strings.Contains(msg, "rego_compile_error")
}

// bundledOPAVersion returns the version of the OPA module bundled in this
// binary, or "unknown" if it cannot be determined.
func bundledOPAVersion() string {
	info, ok := readBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == opaModulePath {
			return dep.Version
		}
	}
	return "unknown"
}

// wrapRegoError inspects err for OPA/Rego compilation error patterns
// (rego_type_error, rego_parse_error, rego_compile_error). If found, it wraps
// the error with a user-friendly message that includes the bundled OPA version
// and remediation guidance. Non-matching errors are returned as-is.
func wrapRegoError(err error) error {
	if !isRegoCompilationError(err) {
		return err
	}

	version := bundledOPAVersion()

	versionSuffix := ""
	adjustLine := ""
	if version != "unknown" {
		versionSuffix = " (" + version + ")"
		adjustLine = fmt.Sprintf(".\n    Adjust the policy to target OPA %s or earlier", version)
	}

	return fmt.Errorf("policy compilation error: the policy references Rego built-in "+
		"functions not available in this version of Conforma CLI%s.\n\n"+
		"Upgrade Conforma CLI to a newer version that includes the required functions.\n\n"+
		"If upgrading does not help, check for less common causes:\n"+
		"  - Conforma CLI disables certain built-in functions for security "+
		"(%s). Policies using these will not compile regardless of the CLI version\n"+
		"  - The policy may use Rego syntax requiring a newer OPA version%s\n\n"+
		"Details:\n  %w", versionSuffix, strings.Join(disallowedBuiltins, ", "), adjustLine, err)
}
