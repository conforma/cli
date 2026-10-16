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

//go:build js && wasm

package main

import (
	"context"
	"syscall/js"
)

func main() {
	js.Global().Set("conformaPlaygroundValidate", js.FuncOf(func(_ js.Value, args []js.Value) any {
		policyText := ""
		inputText := ""
		if len(args) > 0 {
			policyText = args[0].String()
		}
		if len(args) > 1 {
			inputText = args[1].String()
		}

		report := evaluatePlayground(context.Background(), policyText, inputText)
		return marshalReport(report)
	}))

	select {}
}
