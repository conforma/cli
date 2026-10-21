package lib.pipeline

import rego.v1

has_required_task(snapshot, task_name) if {
	some task in snapshot.pipeline.tasks
	task.name == task_name
}
