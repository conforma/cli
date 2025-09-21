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
	"context"

	hd "github.com/MakeNowJust/heredoc/v2"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

type sigstoreInitializeFunc func(ctx context.Context, root, mirror string) error

func sigstoreInitializeCmd(f sigstoreInitializeFunc) *cobra.Command {

	opts := &options.InitializeOptions{}

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initializes Sigstore root to retrieve trusted certificate and key targets for verification",

		Long: hd.Doc(`
			Initializes Sigstore root to retrieve trusted certificate and key targets for verification.

			The following options are used by default:
			- The current trusted Sigstore TUF root is embedded inside ec at the time of release.
			- Sigstore remote TUF repository is pulled from the CDN mirror at tuf-repo-cdn.sigstore.dev.

			To provide an out-of-band trusted initial root.json, use the --root flag with a file or
			URL reference. This will enable you to point ec to a separate TUF root.

			Any updated TUF repository will be written to $HOME/.sigstore/root/.

			Trusted keys and certificate used in ec verification (e.g. verifying Fulcio issued certificates
			with Fulcio root CA) are pulled form the trusted metadata.

			This command is mostly a wrapper around "cosign initialize".
		`),

		Example: hd.Doc(`
			ec initialize -mirror <url> -out <file>

			Initialize root with distributed root keys, default mirror, and default out path.
			ec initialize

			Initialize with an out-of-band root key file, using the default mirror.
			ec initialize -root <url>

			Initialize with an out-of-band root key file and custom repository mirror.
			ec initialize -mirror <url> -root <url>
		`),

		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return f(cmd.Context(), opts.Root, opts.Mirror)
		},
	}

	opts.AddFlags(cmd)

	return cmd
}
