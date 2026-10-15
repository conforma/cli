# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0

#
# METADATA
# title: CHI release checks
# description: >-
#   Check verified CHI attestations for each image and reject CRITICAL advisories
#   whose safe_until deadline has passed.
# entrypoint: true
#
package chi

import rego.v1

import data.lib.metadata
import data.lib.time as lib_time

_predicate_type := "https://example.invalid/chi/v1"

_chi_attestations := [att |
	some att in input.attestations
	att.statement.predicateType == _predicate_type
]

_slsa_attestations := [att |
	some att in input.attestations
	att.statement.predicateType in {"https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"}
]

# METADATA
# title: CHI attestation found
# description: Require exactly one verified CHI attestation for the image.
# custom:
#   short_name: coverage
#   failure_msg: Expected exactly one CHI attestation for this image
#   solution: Supply one signed CHI attestation whose subject digest matches the image.
#   collections:
#   - redhat
#   effective_on: 2026-01-01T00:00:00Z
#
deny contains result if {
	count(_chi_attestations) != 1
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Valid CHI predicate
# description: Require a CRITICAL advisory map with valid dates and boolean blocked values.
# custom:
#   short_name: format
#   failure_msg: >-
#     Invalid CHI predicate: require a CRITICAL object with released_on and
#     safe_until RFC3339 dates, safe_until >= released_on, and boolean blocked values
#   solution: Have the collector calculate valid deadlines and attest the resulting predicate.
#   collections:
#   - redhat
#   effective_on: 2026-01-01T00:00:00Z
#
deny contains result if {
	some att in _chi_attestations
	not _valid_predicate(object.get(att.statement, "predicate", null))
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: OCI provenance found
# description: Verify that SLSA provenance is available alongside the CHI attestation.
# custom:
#   short_name: provenance
#   failure_msg: Missing SLSA provenance from OCI
#   solution: Supply verified SLSA provenance for this image in the registry.
#   collections:
#   - redhat
#   effective_on: 2026-01-01T00:00:00Z
#
deny contains result if {
	count(_slsa_attestations) == 0
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: CRITICAL advisory deadline
# description: Reject CRITICAL advisories at or after their safe_until deadline.
# custom:
#   short_name: release_gate
#   failure_msg: CRITICAL advisory %s has reached its safe_until deadline (%s)
#   solution: Remediate the CRITICAL advisory before releasing the image.
#   collections:
#   - redhat
#   effective_on: 2026-01-01T00:00:00Z
#
deny contains result if {
	some att in _chi_attestations
	some advisory, record in att.statement.predicate.CRITICAL
	lib_time.effective_current_time_ns >= time.parse_rfc3339_ns(record.safe_until)
	result := metadata.result_helper_with_term(rego.metadata.chain(), [advisory, record.safe_until], advisory)
}

# The filesystem source already matched each verified statement's signed
# subject digest to this image. The predicate needs no additional image label.
_valid_predicate(predicate) if {
	is_object(predicate)
	is_object(predicate.CRITICAL)
	every advisory, record in predicate.CRITICAL {
		advisory != ""
		_valid_advisory(record)
	}
}

_valid_advisory(record) if {
	is_object(record)
	is_boolean(record.blocked)
	is_string(record.released_on)
	is_string(record.safe_until)
	released := time.parse_rfc3339_ns(record.released_on)
	deadline := time.parse_rfc3339_ns(record.safe_until)
	deadline >= released
}
