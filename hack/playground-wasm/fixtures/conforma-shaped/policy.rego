# file: main.rego
package main

import rego.v1

import data.lib.pipeline
import data.lib.release

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

warn contains result if {
	not input.metadata.labels["appstudio.openshift.io/application"]
	result := {
		"code": "main.application_label_missing",
		"msg": "application label is recommended",
	}
}

# file: lib/pipeline.rego
package lib.pipeline

import rego.v1

has_required_task(snapshot, task_name) if {
	some task in snapshot.pipeline.tasks
	task.name == task_name
}

# file: lib/release.rego
package lib.release

import rego.v1

allowed_signer(signer) if {
	data.allowed_signers[_] == signer
}
