#!/usr/bin/env python3
"""Fetch archived Tekton TaskRun logs for a PipelineRun from KubeArchive.

PipelineRuns in Konflux are vacuumed out of the live cluster and into
KubeArchive, so `oc logs` / `tkn pr logs` stop working once they're gone.
KubeArchive mirrors the Kubernetes API and serves archived logs via a
`/log` subresource, selecting a step with `?container=<step-container>`.

Usage:
    python hack/ka-logs.py ec-main-enterprise-contract-vqbjs
    python hack/ka-logs.py <pipelinerun> -n <namespace>
    python hack/ka-logs.py <pipelinerun> --task verify   # only one pipelineTask

Auth and the KubeArchive route are discovered via `oc` (you must be logged
in). Override with the KUBEARCHIVE_HOST / KUBEARCHIVE_TOKEN env vars.
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

DEFAULT_NAMESPACE = "rhtap-contract-tenant"
KUBEARCHIVE_ROUTE_NS = "product-kubearchive"
KUBEARCHIVE_ROUTE = "kubearchive-api-server"


def eprint(*args):
    print(*args, file=sys.stderr)


def oc(*args):
    """Run an oc command and return stripped stdout, or raise on failure."""
    try:
        out = subprocess.run(
            ["oc", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        sys.exit("error: `oc` not found on PATH")
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: `oc {' '.join(args)}` failed:\n{e.stderr.strip()}")
    return out.stdout.strip()


def discover_host():
    host = os.environ.get("KUBEARCHIVE_HOST")
    if host:
        return host
    return oc(
        "get", "route", KUBEARCHIVE_ROUTE,
        "-n", KUBEARCHIVE_ROUTE_NS,
        "-o", "jsonpath={.spec.host}",
    )


def discover_token():
    return os.environ.get("KUBEARCHIVE_TOKEN") or oc("whoami", "-t")


class Client:
    def __init__(self, host, token):
        self.host = host
        self.token = token
        # KubeArchive uses a re-encrypt route; skip verification like `oc`'s
        # -k does here, since the CLI is talking to a known cluster route.
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _get(self, path, params=None):
        url = f"https://{self.host}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, context=self.ctx) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def get_json(self, path, params=None):
        status, body = self._get(path, params)
        if status != 200:
            raise RuntimeError(f"HTTP {status} for {path}: {body[:200]}")
        return json.loads(body)

    def get_log(self, ns, taskrun, container):
        return self._get(
            f"/apis/tekton.dev/v1/namespaces/{ns}/taskruns/{taskrun}/log",
            {"container": container},
        )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pipelinerun", help="PipelineRun name")
    ap.add_argument("-n", "--namespace", default=DEFAULT_NAMESPACE)
    ap.add_argument("--task", help="only dump this pipelineTask (e.g. verify)")
    ap.add_argument("--no-headers", action="store_true", help="raw logs only, no separators")
    args = ap.parse_args()

    client = Client(discover_host(), discover_token())
    base = f"/apis/tekton.dev/v1/namespaces/{args.namespace}"

    pr = client.get_json(f"{base}/pipelineruns/{args.pipelinerun}")
    children = [
        c for c in pr.get("status", {}).get("childReferences", [])
        if c.get("kind") == "TaskRun"
    ]
    if args.task:
        children = [c for c in children if c.get("pipelineTaskName") == args.task]
    if not children:
        sys.exit(f"error: no matching TaskRuns for {args.pipelinerun}")

    for child in children:
        tr_name = child["name"]
        task = child.get("pipelineTaskName", "?")
        tr = client.get_json(f"{base}/taskruns/{tr_name}")
        steps = tr.get("status", {}).get("steps", [])
        for step in steps:
            container = step.get("container")
            if not container:
                continue
            status, body = client.get_log(args.namespace, tr_name, container)
            step_name = step.get("name")
            if not args.no_headers:
                term = step.get("terminated", {})
                exit_code = term.get("exitCode", "?")
                eprint(f"===== task={task} step={step_name} "
                       f"container={container} exit={exit_code} http={status} =====")
            if status == 200:
                prefix = f"[{task} : {step_name}] "
                for line in body.splitlines():
                    sys.stdout.write(prefix + line + "\n")
            elif not args.no_headers:
                eprint(f"  (no log: HTTP {status})")


if __name__ == "__main__":
    main()
