package task_bundle

import rego.v1

# Check if the current image is a Tekton task bundle
_is_task_bundle if {
	_manifest != null
	some layer in _manifest.layers
	_is_tekton_layer(layer)
}

_manifest := ec.oci.image_manifest(input.image.ref)

_is_tekton_layer(layer) if {
	layer.annotations["dev.tekton.image.kind"]
	layer.annotations["dev.tekton.image.name"]
	layer.annotations["dev.tekton.image.apiVersion"]
}

# ===== Extraction =====

# Extract all task definitions from the bundle
_task_definitions := [task |
	_is_task_bundle
	some layer in _manifest.layers
	layer.annotations["dev.tekton.image.kind"] == "task"
	task_name := layer.annotations["dev.tekton.image.name"]

	# Build blob reference: repo@digest
	blob_ref := sprintf("%s@%s", [_repo, layer.digest])

	# Extract task definition from blob
	task := _extract_task(blob_ref, task_name)
	task != null
]

_repo := repo if {
	parts := split(input.image.ref, "@")
	repo := parts[0]
}

# Extract task definition from the blob tar archive.
# Tekton bundles store each task as a tar entry named after the task (no file extension).
_extract_task(blob_ref, task_name) := task if {
	files := ec.oci.blob_files(blob_ref, [task_name])
	task := files[task_name]
}

# ===== Validation rules =====

# METADATA
# title: Task bundle detected
# description: Reports that a Tekton task bundle was detected and how many tasks were extracted.
# custom:
#   short_name: detected
warn contains result if {
	_is_task_bundle
	count(_task_definitions) > 0
	result := {
		"code": "task_bundle.detected",
		"msg": sprintf("Detected task bundle with %d task(s) extracted", [count(_task_definitions)]),
	}
}

# METADATA
# title: No tasks extracted
# description: A task bundle was detected but no tasks could be extracted from it.
# custom:
#   short_name: no_tasks
deny contains result if {
	_is_task_bundle
	count(_task_definitions) == 0
	result := {
		"code": "task_bundle.no_tasks",
		"msg": sprintf("Task bundle detected but no tasks could be extracted from %s", [input.image.ref]),
	}
}

# METADATA
# title: Task kind validation
# description: Each task definition in the bundle must have kind set to "Task".
# custom:
#   short_name: kind
deny contains result if {
	some task in _task_definitions
	task.kind != "Task"
	result := {
		"code": "task_bundle.kind",
		"msg": sprintf("Task %s has invalid kind '%s', expected 'Task'", [_task_name(task), task.kind]),
	}
}

# METADATA
# title: Task metadata.name required
# description: Each task definition must have metadata.name set.
# custom:
#   short_name: name_required
deny contains result if {
	some task in _task_definitions
	not task.metadata.name
	result := {
		"code": "task_bundle.name_required",
		"msg": "Task is missing metadata.name",
	}
}

# METADATA
# title: Task has steps
# description: Each task must define at least one step.
# custom:
#   short_name: has_steps
deny contains result if {
	some task in _task_definitions
	not task.spec.steps
	result := {
		"code": "task_bundle.has_steps",
		"msg": sprintf("Task %s has no steps defined", [_task_name(task)]),
	}
}

deny contains result if {
	some task in _task_definitions
	task.spec.steps
	count(task.spec.steps) == 0
	result := {
		"code": "task_bundle.has_steps",
		"msg": sprintf("Task %s has empty steps", [_task_name(task)]),
	}
}

# METADATA
# title: Step has image
# description: Each step in a task must specify a container image.
# custom:
#   short_name: step_image
deny contains result if {
	some task in _task_definitions
	task.spec.steps
	some i, step in task.spec.steps
	not step.image
	not step.ref # Steps using a StepAction ref don't need an image
	result := {
		"code": "task_bundle.step_image",
		"msg": sprintf("Task %s step[%d] '%s' is missing image", [_task_name(task), i, object.get(step, "name", "<unnamed>")]),
	}
}

_task_name(task) := task.metadata.name if {
	task.metadata.name
}

_task_name(task) := "<unnamed>" if {
	not task.metadata.name
}
