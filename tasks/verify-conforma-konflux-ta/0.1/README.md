# Verify Conforma Task

NOTE: Conforma was previously known as "Enterprise Contract". You can consider
"Conforma" and "Enterprise Contract" to be synonymous. Note that the Tekton task defined here is still
referencing the older name. See [this article](https://conforma.dev/posts/whats-in-a-name/) for more details
about the name change.

This task verifies a signature and attestation for an image and then runs a policy against the image's attestation using the ```ec validate image``` command.
It makes use of [Trusted Artifacts](https://github.com/konflux-ci/build-trusted-artifacts) to securely share the Snapshot between the calling Pipeline
and this Task.

## Install the task
kubectl apply -f https://raw.githubusercontent.com/conforma/cli/main/tasks/verify-conforma-konflux-ta/0.1/verify-conforma-konflux-ta.yaml

## Parameters
### Required
* **SNAPSHOT_FILENAME**: The filename of the `Snapshot` that is located within the trusted artifact
* **SOURCE_DATA_ARTIFACT**: Trusted Artifact to use to obtain the Snapshot to validate.

### Optional
* **POLICY_CONFIGURATION**: Name of the policy configuration (EnterpriseContractPolicy resource) to use. `namespace/name` or `name` syntax supported. If namespace is omitted the namespace where the task runs is used. You can also specify a policy configuration using a git url, e.g. `github.com/conforma/config//slsa3`. (default: "enterprise-contract-service/default")
* **PUBLIC_KEY**: Public key used to verify signatures. Must be a valid k8s cosign reference, e.g. k8s://my-space/my-secret where my-secret contains the expected cosign.pub attribute. (default: "")
* **REKOR_HOST**: Rekor host for transparency log lookups (default: "")
* **IGNORE_REKOR**: Skip Rekor transparency log checks during validation. (default: "false")
* **TUF_MIRROR**: TUF mirror URL. Provide a value when NOT using public sigstore deployment. (default: "")
* **SSL_CERT_DIR**: Path to a directory containing SSL certs to be used when communicating with external services. This is useful when using the integrated registry and a local instance of Rekor on a development cluster which may use certificates issued by a not-commonly trusted root CA. In such cases, `/var/run/secrets/kubernetes.io/serviceaccount` is a good value. Multiple paths can be provided by using the `:` separator. (default: "")
* **CA_TRUST_CONFIGMAP_NAME**: The name of the ConfigMap to read CA bundle data from. (default: "trusted-ca")
* **CA_TRUST_CONFIG_MAP_KEY**: The name of the key in the ConfigMap that contains the CA bundle data. (default: "ca-bundle.crt")
* **INFO**: Include rule titles and descriptions in the output. Set to `"false"` to disable it. (default: "true")
* **STRICT**: Fail the task if policy fails. Set to `"false"` to disable it. (default: "true")
* **HOMEDIR**: Value for the HOME environment variable. (default: "/tekton/home")
* **EFFECTIVE_TIME**: Run policy checks with the provided time. (default: "now")
* **EXTRA_RULE_DATA**: Merge additional Rego variables into the policy data. Use syntax "key=value,key2=value2..." (default: "")
* **TIMEOUT**: This param is deprecated and will be removed in future. Its value is ignored. EC will be run without a timeout. (If you do want to apply a timeout use the Tekton task timeout.) (default: "")
* **WORKERS**: Number of parallel workers to use for policy evaluation. This parameter is currently not used. All policy evaluations are run with 35 workers. (default: "35")
* **SINGLE_COMPONENT**: Reduce the Snapshot to only the component whose build caused the Snapshot to be created (default: "false")
* **SINGLE_COMPONENT_CUSTOM_RESOURCE**: Name, including kind, of the Kubernetes resource to query for labels when single component mode is enabled, e.g. pr/somepipeline. (default: "unknown")
* **SINGLE_COMPONENT_CUSTOM_RESOURCE_NS**: Kubernetes namespace where the SINGLE_COMPONENT_NAME is found. Only used when single component mode is enabled. (default: "")
* **ORAS_OPTIONS**: oras options to pass to Trusted Artifacts calls (default: "")
* **TRUSTED_ARTIFACTS_DEBUG**: Flag to enable debug logging in trusted artifacts. Set to a non-empty string to enable. (default: "")
* **TRUSTED_ARTIFACTS_EXTRACT_DIR**: Directory to use to extract trusted artifact archive. (default: "/var/workdir/conforma")
* **RETRY_DURATION**: Base duration for exponential backoff calculation (e.g., "1s", "500ms") (default: "1s")
* **RETRY_FACTOR**: Exponential backoff multiplier (e.g., "2.0", "1.5") (default: "2.0")
* **RETRY_JITTER**: Randomness factor for backoff calculation (0.0-1.0, e.g., "0.1", "0.2") (default: "0.1")
* **RETRY_MAX_RETRY**: Maximum number of retry attempts (default: "3")
* **RETRY_MAX_WAIT**: Maximum wait time between retries (e.g., "3s", "10s") (default: "3s")

## Usage

This TaskRun runs the Task to verify an image. This assumes a policy is created and stored on the cluster with the namespaced name of `enterprise-contract-service/default`. For more information on creating a policy, refer to the Conforma [documentation](https://conforma.dev/docs/ecc/index.html).

```yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  name: verify-conforma-konflux-ta-run
spec:
  taskRef:
    name: verify-conforma-konflux-ta
  params:
    - name: SNAPSHOT_FILENAME
      value: 'snapshot.json'
    - name: SOURCE_DATA_ARTIFACT
      value: "$(tasks.mytask.results.sourceDataArtifact)"
```

### Example with custom retry configuration

```yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  name: verify-conforma-with-retry
spec:
  taskRef:
    name: verify-conforma-konflux-ta
  params:
  - name: SNAPSHOT_FILENAME
    value: 'snapshot.json'
  - name: SOURCE_DATA_ARTIFACT
    value: "$(tasks.mytask.results.sourceDataArtifact)"
  - name: RETRY_DURATION
    value: "2s"
  - name: RETRY_FACTOR
    value: "1.5"
  - name: RETRY_JITTER
    value: "0.2"
  - name: RETRY_MAX_RETRY
    value: "5"
  - name: RETRY_MAX_WAIT
    value: "10s"
```
