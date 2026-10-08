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

package track

import (
	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/tracker"
)

var TrackCmd *cobra.Command

func init() {
	TrackCmd = NewTrackCmd()
	TrackCmd.AddCommand(trackBundleCmd(tracker.Track, tracker.PullImage, tracker.PushImage))
}

func NewTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track",
		Short: "Record resource references for tracking purposes",
		Long: hd.Doc(`
			Record resource references for tracking purposes

			Deprecated: This command is deprecated and will be removed in a future
			release.
		`),
	}
}
