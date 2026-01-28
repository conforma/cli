# Policy to validate volatile config schema contract between ec-cli and ec-policies.
# This serves as an integration test to ensure the input schema is correctly populated.
# The warning patterns here align with policy/release/volatile_config/volatile_config.rego
package main

import rego.v1

# Warn for volatile rules pending activation (effectiveOn in future)
warn contains result if {
	some source in input.policy_spec.sources
	some config in source.volatileConfig.exclude
	config.effectiveOn
	_is_future_date(config.effectiveOn)
	result := {
		"msg": sprintf("Volatile exclude rule '%s' is pending activation (effective on: %s)", [config.value, config.effectiveOn]),
	}
}

# Warn for volatile rules that will expire (effectiveUntil in future)
warn contains result if {
	some source in input.policy_spec.sources
	some config in source.volatileConfig.exclude
	config.effectiveUntil
	not _is_past_date(config.effectiveUntil)
	result := {
		"msg": sprintf("Volatile exclude rule '%s' will expire (effective until: %s)", [config.value, config.effectiveUntil]),
	}
}

# Warn for volatile rules with no expiration date
warn contains result if {
	some source in input.policy_spec.sources
	some config in source.volatileConfig.exclude
	not config.effectiveUntil
	not config.effectiveOn
	result := {
		"msg": sprintf("Volatile exclude rule '%s' has no expiration date set", [config.value]),
	}
}

# Warn for volatile rules scoped to component names (proves componentNames is accessible)
warn contains result if {
	some source in input.policy_spec.sources
	some config in source.volatileConfig.exclude
	count(config.componentNames) > 0
	some name in config.componentNames
	name == input.component_name
	result := {
		"msg": sprintf("Volatile exclude rule '%s' is scoped to component '%s'", [config.value, input.component_name]),
	}
}

# Helper to check if date is in the future
_is_future_date(date_str) if {
	date_str != ""
	date_ns := time.parse_rfc3339_ns(date_str)
	now_ns := time.now_ns()
	date_ns > now_ns
}

# Helper to check if date is in the past
_is_past_date(date_str) if {
	date_str != ""
	date_ns := time.parse_rfc3339_ns(date_str)
	now_ns := time.now_ns()
	date_ns < now_ns
}
