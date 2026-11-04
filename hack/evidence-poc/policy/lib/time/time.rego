# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0

# Standalone counterparts to the release bundle's metadata time helpers.
package lib.time

import rego.v1

default_effective_on := "2022-01-01T00:00:00Z"

when(chain) := effective_on if {
	all_effective_on := [annotation.annotations.custom.effective_on |
		some annotation in chain
		annotation.annotations.scope in {"rule", "document", "package"}
	]
	effective_on := array.concat(all_effective_on, [default_effective_on])[0]
}

effective_current_time_ns := now_ns if {
	data.config
	now_ns := object.get(data.config, ["policy", "when_ns"], time.now_ns())
}

effective_current_time_ns := now_ns if {
	not data.config
	now_ns := time.now_ns()
}
