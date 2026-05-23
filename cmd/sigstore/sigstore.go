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

package sigstore

import (
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/initialize"
	"github.com/spf13/cobra"

	_ "github.com/conforma/cli/internal/rego"
)

var SigstoreCmd *cobra.Command

func init() {
	SigstoreCmd = NewSigstoreCmd()
	SigstoreCmd.AddCommand(sigstoreInitializeCmd(initialize.DoInitialize))
}

func NewSigstoreCmd() *cobra.Command {
	sigstoreCmd := &cobra.Command{
		Use:   "sigstore",
		Short: "Perform certain sigstore operations",
	}
	return sigstoreCmd
}
