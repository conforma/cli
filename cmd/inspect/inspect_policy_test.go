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

//go:build unit

package inspect

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	fileMetadata "github.com/conforma/go-gather/gather/file"
	"github.com/conforma/go-gather/metadata"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/cmd/root"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) (metadata.Metadata, error) {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Get(0).(metadata.Metadata), args.Error(1)
}

func TestFetchSourcesFromPolicy(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
		if err := afero.WriteFile(fs, fmt.Sprintf("%s/foo.rego", args.String(0)), []byte("package foo\n\nbar = 1"), 0644); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)

	inspectPolicyCmd := inspectPolicyCmd()
	cmd := setUpCobra(inspectPolicyCmd)
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"inspect",
		"policy",
		"--policy",
		`{"sources":[{"policy":["one","two"]},{"policy":["three"]}]}`,
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Equal(t, "[one,two,three]", inspectPolicyCmd.Flag("source").Value.String())
	assert.Equal(t, "# Source: file::one\n\n# Source: file::three\n\n# Source: file::two\n\n", buffy.String())
}

func TestFetchSources(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
		if err := afero.WriteFile(fs, fmt.Sprintf("%s/foo.rego", args.String(0)), []byte("package foo\n\nbar = 1"), 0644); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(&fileMetadata.FSMetadata{}, nil).Run(createDir)

	inspectPolicyCmd := inspectPolicyCmd()
	cmd := setUpCobra(inspectPolicyCmd)
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"inspect",
		"policy",
		"--source",
		"one",
		"--source",
		"two",
		"--source",
		"three",
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Equal(t, "[one,two,three]", inspectPolicyCmd.Flag("source").Value.String())
	assert.Equal(t, "# Source: file::one\n\n# Source: file::three\n\n# Source: file::two\n\n", buffy.String())
}

func TestSourcesAndPolicyCantBeBothProvided(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(nil).Run(createDir)

	inspectPolicyCmd := inspectPolicyCmd()
	cmd := setUpCobra(inspectPolicyCmd)
	cmd.SetContext(ctx)

	cmd.SetArgs([]string{
		"inspect",
		"policy",
		"--source",
		"one",
		"--source",
		"two",
		"--source",
		"three",
		"--policy",
		`{"sources":[{"policy":["one","two"]},{"policy":["three"]}]}`,
	})

	err := cmd.Execute()
	assert.Error(t, err, "if any flags in the group [policy source] are set none of the others can be; [policy source] were all set")
}

func setUpCobra(command *cobra.Command) *cobra.Command {
	inspectCmd := NewInspectCmd()
	inspectCmd.AddCommand(command)
	cmd := root.NewRootCmd()
	cmd.AddCommand(inspectCmd)
	return cmd
}
