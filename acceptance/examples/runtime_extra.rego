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

package runtime_extra

import rego.v1

# METADATA
# title: Runtime extra data available
# description: The extra JSON file from the trusted artifact is available as runtime policy data.
# custom:
#   short_name: available
deny contains result if {
    not data.runtime_extra.some_result
    result := {
        "code": "runtime_extra.available",
        "msg": "Runtime extra data was not loaded",
    }
}

# METADATA
# title: Runtime extra data warning
# description: Just so we can see something in the text output snaps
# custom:
#   short_name: bacon_check
warn contains result if {
    not data.runtime_extra.some_result == "bacon"
    result := {
        "code": "runtime_extra.bacon_check",
        "msg": "Bacon not found"
    }
}
