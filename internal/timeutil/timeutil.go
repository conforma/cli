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

package timeutil

import (
	"fmt"
	"time"
)

// Must match policy.DateFormat.
const DateFormat = "2006-01-02"

// ParseVolatileTime tries RFC3339 first, then date-only ("2006-01-02") as a
// fallback, matching the convention used in policy.ParseEffectiveTime.
func ParseVolatileTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(DateFormat, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unable to parse %q as RFC3339 or %s", s, DateFormat)
}
