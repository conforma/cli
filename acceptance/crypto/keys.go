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

// Package crypto handles key and signer creation
package crypto

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/conforma/cli/acceptance/testenv"
)

type keys int

// we store all generated keys in the Context under this key
const keyStateKey = keys(0)

type keyState struct {
	Keys map[string]*cosign.KeysBytes
}

func (g keyState) Key() any {
	return keyStateKey
}

// GenerateKeyPair generates a key pair with no password protection
func GenerateKeyPair() (*cosign.KeysBytes, error) {
	return cosign.GenerateKeyPair(nil)
}

// GenerateKeyPairNamed generates a key pair and stores it in the Context
func GenerateKeyPairNamed(ctx context.Context, name string) (context.Context, error) {
	var state *keyState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Keys[name] != nil {
		// key with this name was already generated
		return ctx, nil
	}

	keyPair, err := GenerateKeyPair()
	if err != nil {
		return ctx, err
	}

	if state.Keys == nil {
		state.Keys = make(map[string]*cosign.KeysBytes)
	}

	state.Keys[name] = keyPair

	return ctx, nil
}

// allKeysFrom returns all key pairs from the Context
func allKeysFrom(ctx context.Context) map[string]*cosign.KeysBytes {
	if !testenv.HasState[keyState](ctx) {
		return nil
	}

	return testenv.FetchState[keyState](ctx).Keys
}

// keyWithNameFrom returns a specific key by name from the Context
func keyWithNameFrom(ctx context.Context, name string) (*cosign.KeysBytes, error) {
	keys := allKeysFrom(ctx)

	key := keys[name]
	if key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("can't find key named %s, did you create the key pair beforehand", name)
}

// SignerWithKey configures a SignerVerifier with the provided key by name
func SignerWithKey(ctx context.Context, keyName string) (signature.SignerVerifier, error) {
	key, err := keyWithNameFrom(ctx, keyName)
	if err != nil {
		return nil, err
	}

	return cosign.LoadPrivateKey(key.PrivateBytes, key.Password(), nil)
}

// PublicKeysFrom returns a map of all public keys encoded in PEM format
// keyed by the name of the key
func PublicKeysFrom(ctx context.Context) map[string]string {
	keys := allKeysFrom(ctx)

	ret := make(map[string]string, len(keys))
	for name, key := range keys {
		ret[name] = string(key.PublicBytes)
	}

	return ret
}

// PrivateKeysFrom returns a map of all private keys encoded in PEM format
// keyed by the name of the key
func PrivateKeysFrom(ctx context.Context) map[string]string {
	keys := allKeysFrom(ctx)

	ret := make(map[string]string, len(keys))
	for name, key := range keys {
		ret[name] = string(key.PrivateBytes)
	}

	return ret
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a key pair named "([^"]*)"$`, GenerateKeyPairNamed)
}
