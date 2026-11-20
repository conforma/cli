# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0

# This POC evaluates CHI as a separate source group, without the release
# bundle's libraries. Provide the same result-helper interface used by the
# release rules so chi.rego can move to that bundle without changing its rules.
package lib.metadata

import rego.v1

import data.lib.time as lib_time

result_helper(chain, params) := result if {
	annotation := chain[0].annotations.custom
	path := chain[0].path
	package_name := concat(".", array.slice(path, 0, count(path) - 1))
	result := {
		"code": sprintf("%s.%s", [package_name, annotation.short_name]),
		"msg": sprintf(annotation.failure_msg, params),
		"collections": annotation.collections,
		"effective_on": lib_time.when(chain),
	}
}

result_helper_with_term(chain, params, term) := object.union(
	result_helper(chain, params),
	{"term": term},
)
