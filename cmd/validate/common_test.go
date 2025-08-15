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

//go:build unit || integration

package validate

import (
	"context"

	"github.com/conforma/go-gather/metadata"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/cmd/root"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func commonMockClient(client *fake.FakeClient) {
	// TODO: Replace mock.Anything calls with specific values
	client.On("Head", mock.Anything).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
}

type MockDownloader struct {
	mock.Mock
}

func (m *MockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) (metadata.Metadata, error) {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Get(0).(metadata.Metadata), args.Error(1)
}

func setUpCobra(command *cobra.Command) *cobra.Command {
	validateCmd := NewValidateCmd()
	validateCmd.AddCommand(command)
	cmd := root.NewRootCmd()
	cmd.AddCommand(validateCmd)
	return cmd
}
