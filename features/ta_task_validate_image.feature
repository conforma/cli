Feature: Verify Conforma Trusted Artifact Tekton Task
  Verify Conforma Tekton Task feature scenarios

  Background:
    Given a cluster running
    Given stub tuf running
    Given stub git daemon running

  Scenario: Golden container image with trusted artifacts
    Given a working namespace
    Given a snapshot artifact with content:
      ```
      {
		    "components": [
			    {
			      "containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"
			    }
		    ]
		  }
      ```
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "git::github.com/conforma/policy//policy/release?ref=d34eab36b23d43748e451004177ca144296bf323",
              "git::github.com/conforma/policy//policy/lib?ref=d34eab36b23d43748e451004177ca144296bf323"
            ],
            "config": {
              "include": [
                "slsa_provenance_available"
              ]
            }
          }
        ]
      }
      ```
    When version 0.1 of the task named "verify-conforma-konflux-ta" is run with parameters:
      | SNAPSHOT_FILENAME       | snapshotartifact                                                                                    |
      | SOURCE_DATA_ARTIFACT    | oci:${REGISTRY}/acceptance/snapshotartifact@${BUILD_SNAPSHOT_DIGEST} |
      | POLICY_CONFIGURATION    | ${NAMESPACE}/${POLICY_NAME}                                                                              |
      | STRICT                  | true                                                                                                     |
      | IGNORE_REKOR            | true                                                                                                     |
      | TRUSTED_ARTIFACTS_DEBUG | "true"                                                                                                   |
      | ORAS_OPTIONS            | --plain-http                                                                                             |
    Then the task should succeed
     And the task logs for step "report-json" should match the snapshot
     And the task results should match the snapshot
     And the task logs for step "show-config" should match the snapshot

  Scenario: VSA generation with predicate format
    Given a working namespace
    Given a snapshot artifact with content:
      ```
      {
		    "components": [
			    {
			      "containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"
			    }
		    ]
		  }
      ```
    When version 0.1 of the task named "verify-conforma-konflux-ta" is run with parameters:
      | SNAPSHOT_FILENAME       | snapshotartifact                                                                                                                                                                                                                                                                                                                                                                                          |
      | SOURCE_DATA_ARTIFACT    | oci:${REGISTRY}/acceptance/snapshotartifact@${BUILD_SNAPSHOT_DIGEST}                                                                                                                                                                                                                                                                                                                                     |
      | POLICY_CONFIGURATION    | {"publicKey":"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\\n-----END PUBLIC KEY-----","sources":[{"policy":["git::github.com/conforma/policy//policy/release?ref=d34eab36b23d43748e451004177ca144296bf323","git::github.com/conforma/policy//policy/lib?ref=d34eab36b23d43748e451004177ca144296bf323"],"config":{"include":["slsa_provenance_available"]}}]} |
      | STRICT                  | true                                                                                                                                                                                                                                                                                                                                                                                                      |
      | IGNORE_REKOR            | true                                                                                                                                                                                                                                                                                                                                                                                                      |
      | ENABLE_VSA              | true                                                                                                                                                                                                                                                                                                                                                                                                      |
      | ATTESTATION_FORMAT      | predicate                                                                                                                                                                                                                                                                                                                                                                                                 |
      | TRUSTED_ARTIFACTS_DEBUG | "true"                                                                                                                                                                                                                                                                                                                                                                                                    |
      | ORAS_OPTIONS            | --plain-http                                                                                                                                                                                                                                                                                                                                                                                              |
    Then the task should succeed
     And the task result "VSA_GENERATED" should equal "true"
     And the task logs for step "report-json" should match the snapshot

  Scenario: Policy configuration passed as JSON string
    Given a working namespace
    Given a snapshot artifact with content:
      ```
      {
        "components": [
          {
            "containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"
          }
        ]
      }
      ```
    When version 0.1 of the task named "verify-conforma-konflux-ta" is run with parameters:
      | SNAPSHOT_FILENAME       | snapshotartifact                                                                                    |
      | SOURCE_DATA_ARTIFACT    | oci:${REGISTRY}/acceptance/snapshotartifact@${BUILD_SNAPSHOT_DIGEST} |
      | POLICY_CONFIGURATION    | {"publicKey":"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\\n-----END PUBLIC KEY-----","sources":[{"policy":["git::github.com/conforma/policy//policy/release?ref=d34eab36b23d43748e451004177ca144296bf323","git::github.com/conforma/policy//policy/lib?ref=d34eab36b23d43748e451004177ca144296bf323"],"config":{"include":["slsa_provenance_available"]}}]} |
      | STRICT                  | true                                                                                                     |
      | IGNORE_REKOR            | true                                                                                                     |
      | TRUSTED_ARTIFACTS_DEBUG | "true"                                                                                                   |
      | ORAS_OPTIONS            | --plain-http                                                                                             |
    Then the task should succeed
     And the task logs for step "show-config" should contain "slsa_provenance_available"
