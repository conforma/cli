// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"math"
)

// SafeAdd safely adds two integers, returning an error if overflow would occur
func SafeAdd(a, b int) (int, error) {
	if a > 0 && b > math.MaxInt-a {
		return 0, fmt.Errorf("integer overflow: %d + %d would exceed MaxInt", a, b)
	}
	if a < 0 && b < math.MinInt-a {
		return 0, fmt.Errorf("integer overflow: %d + %d would exceed MinInt", a, b)
	}
	return a + b, nil
}

// SafeMultiply safely multiplies two integers, returning an error if overflow would occur
func SafeMultiply(a, b int) (int, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}

	// Check for overflow
	if a > 0 && b > 0 {
		if a > math.MaxInt/b {
			return 0, fmt.Errorf("integer overflow: %d * %d would exceed MaxInt", a, b)
		}
	} else if a < 0 && b < 0 {
		if a < math.MaxInt/b {
			return 0, fmt.Errorf("integer overflow: %d * %d would exceed MaxInt", a, b)
		}
	} else if a > 0 && b < 0 {
		if b < math.MinInt/a {
			return 0, fmt.Errorf("integer overflow: %d * %d would exceed MinInt", a, b)
		}
	} else if a < 0 && b > 0 {
		if a < math.MinInt/b {
			return 0, fmt.Errorf("integer overflow: %d * %d would exceed MinInt", a, b)
		}
	}

	return a * b, nil
}

// SafeCapacity calculates a safe capacity for slice allocation
// It prevents integer overflow and provides reasonable fallbacks
func SafeCapacity(base int, multiplier int) int {
	capacity, err := SafeMultiply(base, multiplier)
	if err != nil {
		// Fallback to a reasonable maximum
		return math.MaxInt / 4
	}

	// Additional safety check for extremely large values
	const maxReasonableCapacity = 10000000 // 10 million
	if capacity > maxReasonableCapacity {
		return maxReasonableCapacity
	}

	return capacity
}

// SafeSliceCapacity calculates safe capacity for slice allocation with multiple length additions
func SafeSliceCapacity(lengths ...int) int {
	total := 0
	for _, length := range lengths {
		sum, err := SafeAdd(total, length)
		if err != nil {
			// Fallback to reasonable maximum
			return math.MaxInt / 4
		}
		total = sum
	}

	// Additional safety check
	const maxReasonableCapacity = 10000000 // 10 million
	if total > maxReasonableCapacity {
		return maxReasonableCapacity
	}

	return total
}

// ValidateSliceLength validates that a slice length is within reasonable bounds
func ValidateSliceLength(length int, maxAllowed int) error {
	if length < 0 {
		return fmt.Errorf("negative slice length: %d", length)
	}
	if length > maxAllowed {
		return fmt.Errorf("slice length %d exceeds maximum allowed %d", length, maxAllowed)
	}
	return nil
}
