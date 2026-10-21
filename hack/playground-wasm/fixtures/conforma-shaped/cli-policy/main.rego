package main

import rego.v1

import data.lib.pipeline
import data.lib.release

# METADATA
# title: Required build task is present
# custom:
#   short_name: required_task_missing
deny contains result if {
	not pipeline.has_required_task(input, "build-container")
	result := {
		"code": "main.required_task_missing",
		"msg": "required task build-container is missing",
		"metadata": {
			"component": object.get(input, "component", "unknown"),
		},
	}
}

# METADATA
# title: Attestation signer is allowed
# custom:
#   short_name: signer_not_allowed
deny contains result if {
	not release.allowed_signer(input.attestation.signer)
	result := {
		"code": "main.signer_not_allowed",
		"msg": sprintf("attestation signer %q is not allowed", [input.attestation.signer]),
		"metadata": {
			"signer": input.attestation.signer,
		},
	}
}

# METADATA
# title: Application label is present
# custom:
#   short_name: application_label_missing
warn contains result if {
	not input.metadata.labels["appstudio.openshift.io/application"]
	result := {
		"code": "main.application_label_missing",
		"msg": "application label is recommended",
	}
}
