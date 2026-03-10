#!/usr/bin/env bash
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

# Creates Kubernetes resources for running TUF service inside the cluster

set -o errexit
set -o pipefail
set -o nounset

TUF_PORT="${TUF_PORT:-8080}"

printf -- '---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tuf-port-number
  namespace: tuf-service
data:
  PORT: "%d"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tuf-root-data
  namespace: tuf-service
data:
  root.json: |
    {
      "signatures": [],
      "signed": {
        "_type": "root",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": "2030-12-31T23:59:59Z",
        "keys": {},
        "roles": {},
        "consistent_snapshot": false
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tuf-server
  namespace: tuf-service
  labels:
    app.kubernetes.io/name: tuf-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: tuf-server
  template:
    metadata:
      labels:
        app.kubernetes.io/name: tuf-server
    spec:
      containers:
        - name: tuf-server
          image: docker.io/nginx:1.25-alpine
          ports:
            - name: http
              containerPort: %d
          env:
            - name: NGINX_PORT
              value: "%d"
          volumeMounts:
            - name: tuf-data
              mountPath: /usr/share/nginx/html
              readOnly: true
            - name: nginx-config
              mountPath: /etc/nginx/conf.d/default.conf
              subPath: nginx.conf
      volumes:
        - name: tuf-data
          configMap:
            name: tuf-root-data
        - name: nginx-config
          configMap:
            name: tuf-nginx-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tuf-nginx-config
  namespace: tuf-service
data:
  nginx.conf: |
    server {
        listen %d;
        server_name localhost;
        root /usr/share/nginx/html;

        location / {
            try_files $uri $uri/ =404;
            add_header Access-Control-Allow-Origin *;
            add_header Access-Control-Allow-Methods "GET, OPTIONS";
            add_header Access-Control-Allow-Headers "Content-Type";
        }
    }
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app.kubernetes.io/name: tuf-server
  name: tuf
  namespace: tuf-service
spec:
  ports:
  - name: http
    port: %d
    protocol: TCP
    targetPort: %d
  selector:
    app.kubernetes.io/name: tuf-server
  type: ClusterIP
' "${TUF_PORT}" "${TUF_PORT}" "${TUF_PORT}" "${TUF_PORT}" "${TUF_PORT}" "${TUF_PORT}"
