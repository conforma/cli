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

# Minimal image for acceptance tests. The ec and kubectl binaries are
# pre-built on the host and injected here to avoid the multi-stage Go
# compilation that the production Dockerfile uses.
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest@sha256:7d4e47500f28ac3a2bff06c25eff9127ff21048538ae03ce240d57cf756acd00

RUN microdnf upgrade --assumeyes --nodocs --setopt=keepcache=0 --refresh && microdnf -y --nodocs --setopt=keepcache=0 install gzip jq ca-certificates

ARG EC_BINARY
ARG KUBECTL_BINARY

COPY ${EC_BINARY} /usr/local/bin/ec
COPY ${KUBECTL_BINARY} /usr/local/bin/kubectl
COPY hack/reduce-snapshot.sh /usr/local/bin/

RUN ln -s /usr/local/bin/ec /usr/local/bin/conforma

USER 1001

ENTRYPOINT ["/usr/local/bin/ec"]
