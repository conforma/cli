# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package runtime_data

import rego.v1

# METADATA
# title: Runtime extra data present
# description: The extra JSON file from the trusted artifact is available as runtime policy data.
# custom:
#   short_name: present
deny contains result if {
    object.get(_collector_data, "foo", "") != "bar"
    result := {
        "code": "runtime_data.available",
        "msg": "Collector data was not loaded or had an unexpected value",
    }
}

# METADATA
# title: Always warns
# description: Just so we can see something in the text output snaps
# custom:
#   short_name: bacon_ok
warn contains result if {
    not _collector_data.foo == "bacon"
    result := {
        "code": "runtime_data.bacon_ok",
        "msg": "Bacon was not found in collector data"
    }
}

# In real-life release pipelines we're expecting the collector data gathered by the
# collector task (and produced by the collector pipeline) to be accessible like this.
_collector_data := _runtime_data("collector_data")

# Even though the top level key includes "rule_data" we don't access it like other rule
# data since there's only one place it can be, and there are no overrides or fallbacks.
default _runtime_data(_) := {}
_runtime_data(key) := object.get(data.rule_data__runtime__, key, {})
