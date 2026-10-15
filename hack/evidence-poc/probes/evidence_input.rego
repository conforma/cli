# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0

package evidence_input

import rego.v1

# This probe deliberately denies after reading CLI evidence. The check script
# asserts the exact result and compares it with the original signed bundle.
# Keep this outside the normal policy directory: it is only a test policy.

# METADATA
# title: Observe supplied evidence in Rego
# description: Return the actual input.attestations record read by the evaluator.
# custom:
#   short_name: observed
deny contains {
	"code": "evidence_input.observed",
	"msg": json.marshal({
		"component": input.component_name,
		"image": input.image.ref,
		"attestation": record,
		"ociPredicates": [a.statement.predicateType |
			some a in input.attestations
			a.statement.predicateType in {
				"https://slsa.dev/provenance/v0.2",
				"https://slsa.dev/provenance/v1",
			}
		],
	}),
} if {
	some record in input.attestations
	record.statement.predicateType == "https://example.invalid/chi/v1"
}
