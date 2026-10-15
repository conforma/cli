# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0

package chi_test

import data.chi
import rego.v1

now_ns := time.parse_rfc3339_ns("2026-10-13T12:00:00Z")
expired := {
	"released_on": "2026-08-03T14:37:22Z",
	"safe_until": "2026-09-02T14:37:22Z",
	"blocked": true,
}

future := {
	"released_on": "2026-10-03T14:37:22Z",
	"safe_until": "2026-11-02T14:37:22Z",
	"blocked": false,
}

chi_record(predicate) := {"statement": {
	"predicateType": "https://example.invalid/chi/v1",
	"predicate": predicate,
}}

policy_input(predicate) := {"attestations": [
	{"statement": {"predicateType": "https://slsa.dev/provenance/v0.2"}},
	chi_record(predicate),
]}

violations(predicate, at) := result if {
	result := chi.deny with input as policy_input(predicate)
		with data.config.policy.when_ns as at
}

test_sample_rejects_only_expired_critical if {
	result := violations({"CRITICAL": data.CRITICAL, "IMPORTANT": data.IMPORTANT}, now_ns)
	count(result) == 1
	some finding in result
	finding.code == "chi.release_gate"
	finding.term == "RHSA-2026:58936"
}

test_release_style_result_metadata if {
	violations({"CRITICAL": {"RHSA-test": expired}}, now_ns) == {{
		"code": "chi.release_gate",
		"msg": "CRITICAL advisory RHSA-test has reached its safe_until deadline (2026-09-02T14:37:22Z)",
		"term": "RHSA-test",
		"collections": ["redhat"],
		"effective_on": "2026-01-01T00:00:00Z",
	}}
}

test_sample_uses_30_and_90_day_deadlines if {
	every _, record in data.CRITICAL {
		time.parse_rfc3339_ns(record.safe_until) - time.parse_rfc3339_ns(record.released_on) == time.parse_duration_ns("720h")
	}
	every _, record in data.IMPORTANT {
		time.parse_rfc3339_ns(record.safe_until) - time.parse_rfc3339_ns(record.released_on) == time.parse_duration_ns("2160h")
	}
}

test_future_critical_passes_even_if_blocked_true if {
	record := object.union(future, {"blocked": true})
	violations({"CRITICAL": {"RHSA-test": record}}, now_ns) == set()
}

test_expired_critical_denied_even_if_blocked_false if {
	record := object.union(expired, {"blocked": false})
	result := violations({"CRITICAL": {"RHSA-test": record}}, now_ns)
	count(result) == 1
	some finding in result
	finding.code == "chi.release_gate"
}

test_deadline_boundary if {
	predicate := {"CRITICAL": {"RHSA-test": expired}}
	deadline := time.parse_rfc3339_ns(expired.safe_until)
	violations(predicate, deadline - 1) == set()
	count(violations(predicate, deadline)) == 1
	count(violations(predicate, deadline + 1)) == 1
}

test_expired_important_is_not_denied if {
	violations({"CRITICAL": {}, "IMPORTANT": {"RHSA-test": expired}}, now_ns) == set()
}

test_wrong_predicate_cannot_trigger_critical_rule if {
	base := policy_input({"CRITICAL": {}})
	other := {"statement": {
		"predicateType": "https://example.invalid/other/v1",
		"predicate": {"CRITICAL": {"RHSA-test": expired}},
	}}
	result := chi.deny with input as {"attestations": array.concat(base.attestations, [other])}
		with data.config.policy.when_ns as now_ns
	result == set()
}

test_wrong_predicate_cannot_satisfy_coverage if {
	result := chi.deny with input as {"attestations": [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {"CRITICAL": {}},
	}}]}
	count(result) == 1
	some finding in result
	finding.code == "chi.coverage"
}

test_empty_critical_map_passes if {
	violations({"CRITICAL": {}}, now_ns) == set()
}

test_missing_or_malformed_critical_fails_closed if {
	every predicate in [{}, {"CRITIAL": {}}, {"CRITICAL": []}, {"CRITICAL": null}, null] {
		result := violations(predicate, now_ns)
		count(result) == 1
		some finding in result
		finding.code == "chi.format"
	}
}

test_malformed_advisory_fails_closed if {
	every record in [
		object.remove(future, ["safe_until"]),
		object.union(future, {"safe_until": "released_on + 30 days"}),
		object.union(future, {"safe_until": null}),
		object.union(future, {"blocked": "false"}),
		object.union(future, {"released_on": "2027-01-01T00:00:00Z"}),
		object.union(future, {"released_on": "invalid"}),
		null,
		[],
	] {
		result := violations({"CRITICAL": {"RHSA-test": record}}, now_ns)
		some finding in result
		finding.code == "chi.format"
	}
}

test_missing_predicate_fails_closed if {
	base := policy_input({"CRITICAL": {}})
	result := chi.deny with input as {"attestations": [base.attestations[0], {"statement": {"predicateType": "https://example.invalid/chi/v1"}}]}
	count(result) == 1
	some finding in result
	finding.code == "chi.format"
}

test_duplicate_chi_does_not_hide_expired_advisory if {
	base := policy_input({"CRITICAL": {}})
	result := chi.deny with input as {"attestations": array.concat(base.attestations, [chi_record({"CRITICAL": {"RHSA-test": expired}})])}
		with data.config.policy.when_ns as now_ns
	{finding.code | some finding in result} == {"chi.coverage", "chi.release_gate"}
}

test_wall_clock_used_without_effective_time if {
	result := chi.deny with input as policy_input({"CRITICAL": {"RHSA-test": expired}})
		with data.config as {}
		with time.now_ns as now_ns
	count(result) == 1
	some finding in result
	finding.code == "chi.release_gate"
}
