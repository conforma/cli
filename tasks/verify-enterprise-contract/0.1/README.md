# Verify Enterprise Contract Task

NOTE: Conforma was previously known as "Enterprise Contract". You can consider
"Conforma" and "Enterprise Contract" to be synonymous. Note that the Tekton task defined here is still
referencing the older name. See [this article](https://conforma.dev/posts/whats-in-a-name/) for more details
about the name change.

This task verifies a signature and attestation for an image and then runs a policy against the image's attestation using the ```ec validate image``` command.

## Install the task
kubectl apply -f https://raw.githubusercontent.com/conforma/cli/main/tasks/verify-enterprise-contract/0.1/verify-enterprise-contract.yaml

## Parameters
### Required
* **IMAGES**: A JSON formatted list of images.
### Optional
* **POLICY_CONFIGURATION**: Name or inline policy in JSON configuration to use. For name `namespace/name` or `name` syntax supported. If
        namespace is omitted the namespace where the task runs is used. For inline policy provide the [specification](https://conforma.dev/docs/ecc/reference.html#k8s-api-github-com-enterprise-contract-enterprise-contract-controller-api-v1alpha1-enterprisecontractpolicyspec) as JSON.
* **PUBLIC_KEY**: Public key used to verify signatures. Must be a valid k8s cosign
        reference, e.g. k8s://my-space/my-secret where my-secret contains
        the expected cosign.pub attribute.
* **REKOR_HOST**: Rekor host for transparency log lookups
* **SSL_CERT_DIR**: Path to a directory containing SSL certs to be used when communicating
        with external services.
* **CA_TRUST_CONFIGMAP_NAME**: The name of the ConfigMap to read CA bundle data from.
* **CA_TRUST_CONFIG_MAP_KEY**: The name of the key in the ConfigMap that contains the CA bundle data.
* **STRICT**: Fail the task if policy fails. Set to "false" to disable it.
* **HOMEDIR**: Value for the HOME environment variable.
* **EFFECTIVE_TIME**: Run policy checks with the provided time.
* **WORKERS**: Number of parallel workers to use for validation.
* **RETRY_MIN_WAIT**: Minimum wait time between retries for 429 errors (e.g., "200ms", "1s")
* **RETRY_MAX_WAIT**: Maximum wait time between retries for 429 errors (e.g., "3s", "10s")
* **RETRY_MAX_RETRY**: Maximum number of retries for 429 errors
* **RETRY_DURATION**: Base duration for exponential backoff calculation (e.g., "1s", "500ms")
* **RETRY_FACTOR**: Factor for exponential backoff calculation (e.g., "2.0", "1.5")
* **RETRY_JITTER**: Jitter factor for backoff calculation (0.0-1.0, e.g., "0.1", "0.2")


## Usage

This TaskRun runs the Task to verify an image. This assumes a policy is created and stored on the cluster with hte namespaced name of `enterprise-contract-service/default`. For more information on creating a policy, refer to the Conforma [documentation](https://conforma.dev/docs/ecc/index.html).

```yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  name: verify-enterprise-contract
spec:
  taskRef:
    name: verify-enterprise-contract
  params:
  - name: IMAGES
    value: '{"components": ["containerImage": "quay.io/example/repo:latest"]}'
```

### Example with custom retry configuration

```yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  name: verify-enterprise-contract-with-retry
spec:
  taskRef:
    name: verify-enterprise-contract
  params:
  - name: IMAGES
    value: '{"components": ["containerImage": "quay.io/example/repo:latest"]}'
  - name: RETRY_MIN_WAIT
    value: '1s'
  - name: RETRY_MAX_WAIT
    value: '10s'
  - name: RETRY_MAX_RETRY
    value: '5'
  - name: RETRY_DURATION
    value: '2s'
  - name: RETRY_FACTOR
    value: '1.5'
  - name: RETRY_JITTER
    value: '0.2'
```
