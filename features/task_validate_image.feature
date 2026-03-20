Feature: Verify Enterprise Contract Tekton Tasks
  Verify Enterprise Contract Tekton Task feature scenarios

  Background:
    Given a cluster running
    Given stub rekord running
    Given stub tuf running
    Given stub git daemon running

  Scenario: Golden container image
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release?ref=0de5461c14413484575e63e96ddb514d8ab954b5",
              "github.com/conforma/policy//policy/lib?ref=0de5461c14413484575e63e96ddb514d8ab954b5"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                                                                                                  |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot
     And the task logs for step "show-config" should match the snapshot

  Scenario: Extra rule data provided to task
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release",
              "github.com/conforma/policy//policy/lib"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                                                                                                  |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
      | EXTRA_RULE_DATA      | key1=value1,key2=value2                                                                                                                                      |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Initialize TUF succeeds
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release",
              "github.com/conforma/policy//policy/lib"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                                                                                                  |
      | TUF_MIRROR           | ${TUF}                                                                                                                                                       |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task logs for step "initialize-tuf" should match the snapshot
     And the task results should match the snapshot

  Scenario: Initialize TUF fails
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERhr8Zj4dZW67zucg8fDr11M4lmRp\nzN6SIcIjkvH39siYg1DkCoa2h2xMUZ10ecbM3/ECqvBV55YwQ2rcIEa7XQ==\n-----END PUBLIC KEY-----",
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release",
              "github.com/conforma/policy//policy/lib"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "quay.io/hacbs-contract-demo/golden-container@sha256:e76a4ae9dd8a52a0d191fd34ca133af5b4f2609536d32200a4a40a09fdc93a0d"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                                                                                                  |
      | TUF_MIRROR           | http://tuf.invalid                                                                                                                                           |
      | STRICT               | true                                                                                                                                                         |
      | IGNORE_REKOR         | true                                                                                                                                                         |
    Then the task should fail
     And the task logs for step "report" should match the snapshot
     And the task logs for step "initialize-tuf" should match the snapshot
     And the task results should match the snapshot

  Scenario: Non strict with warnings
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/non-strict-with-warnings"
      And a valid image signature of "acceptance/non-strict-with-warnings" image signed by the "known" key
      And a valid attestation of "acceptance/non-strict-with-warnings" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/buildConfig", "value": {}},{"op": "add", "path": "/predicate/buildConfig/tasks", "value": [{"name":"skipped","results":[{"name":"TEST_OUTPUT","type":"string","value":"{\"result\":\"WARNING\"}"}]}]}] |
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY},
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release",
              "github.com/conforma/policy//policy/lib"
            ],
            "config": {
              "include": [
                "test.no_test_warnings"
              ]
            }
          }
        ]
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/non-strict-with-warnings"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                             |
      | STRICT               | false                                                                                   |
      | IGNORE_REKOR         | true                                                                                    |
    Then the task should succeed
    And the task logs for step "report" should match the snapshot
    And the task results should match the snapshot

  Scenario: Strict with warnings
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/strict-with-warnings"
      And a valid image signature of "acceptance/strict-with-warnings" image signed by the "known" key
      And a valid attestation of "acceptance/strict-with-warnings" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/buildConfig", "value": {}},{"op": "add", "path": "/predicate/buildConfig/tasks", "value": [{"name":"skipped","results":[{"name":"TEST_OUTPUT","type":"string","value":"{\"result\":\"WARNING\"}"}]}]}] |
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY},
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release",
              "github.com/conforma/policy//policy/lib"
            ],
            "config": {
              "include": [
                "test.no_test_warnings"
              ]
            }
          }
        ]
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/strict-with-warnings"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                         |
      | STRICT               | true                                                                                |
      | IGNORE_REKOR         | true                                                                                |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Non strict with failures
    Given a working namespace
      And a key pair named "known"
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/does-not-exist"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | STRICT               | false                                                                         |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should succeed
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Strict with failures
    Given a working namespace
      And a key pair named "known"
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/does-not-exist"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | STRICT               | true                                                                          |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should fail
     And the task logs for step "report" should match the snapshot
     And the task results should match the snapshot

  Scenario: Outputs are there
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/okayish"
      And a valid image signature of "acceptance/okayish" image signed by the "known" key
      And a valid attestation of "acceptance/okayish" signed by the "known" key
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/okayish"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | IGNORE_REKOR         | true                                                                          |
    Then the task should succeed
    And the task logs for step "initialize-tuf" should match the snapshot
     And the task logs for step "report" should match the snapshot
     And the task logs for step "summary" should match the snapshot
     And the task logs for step "assert" should match the snapshot
     And the task logs for step "report-json" should match the snapshot
     And the task results should match the snapshot

  Scenario: Titles and descriptions can be excluded
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/info"
      And a valid image signature of "acceptance/info" image signed by the "known" key
      And a valid attestation of "acceptance/info" signed by the "known" key
      And a cluster policy with content:
      ```
      {"publicKey": ${known_PUBLIC_KEY}}
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/info"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                         |
      | IGNORE_REKOR         | true                                                                |
      | INFO                 | false                                                               |
    Then the task should succeed
      And the task logs for step "report" should match the snapshot
      And the task results should match the snapshot

  Scenario: Effective-time is honored
    Given a working namespace
      And a key pair named "known"
      And an image named "acceptance/effective-time"
      And a valid image signature of "acceptance/effective-time" image signed by the "known" key
      And a valid attestation of "acceptance/effective-time" signed by the "known" key
      And a cluster policy with content:
      ```
      {"publicKey": ${known_PUBLIC_KEY}}
      ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/effective-time"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                   |
      | IGNORE_REKOR         | true                                                                          |
      | EFFECTIVE_TIME       | 2020-01-01T00:00:00Z                                                          |
    Then the task should succeed
      And the task logs for step "show-config" should contain `"effective-time": "2020-01-01T00:00:00Z"`

  Scenario: SSL_CERT_DIR environment variable is customized
    Given a working namespace
    And a key pair named "known"
    And an image named "acceptance/ssl-cert-dir"
    And a valid image signature of "acceptance/ssl-cert-dir" image signed by the "known" key
    And a valid attestation of "acceptance/ssl-cert-dir" signed by the "known" key
    And a cluster policy with content:
    ```
    {"publicKey": ${known_PUBLIC_KEY}}
    ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/ssl-cert-dir"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                 |
      | IGNORE_REKOR         | true                                                                        |
      | SSL_CERT_DIR         | /spam/certs                                                                 |
    Then the task should succeed
      And the task env var for step "validate" named "SSL_CERT_DIR" should be set to "/tekton-custom-certs:/etc/ssl/certs:/etc/pki/tls/certs:/system/etc/security/cacerts:/spam/certs"

  Scenario: PUBLIC_KEY param overwrites key from policy
    Given a working namespace
    And a key pair named "known"
    And an image named "acceptance/public-key-param"
    And a valid image signature of "acceptance/public-key-param" image signed by the "known" key
    And a valid attestation of "acceptance/public-key-param" signed by the "known" key
    And a valid attestation of "acceptance/public-key-param" signed by the "known" key
    And a cluster policy with content:
    ```
    {"publicKey": "ignored"}
    ```
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES               | {"components": [{"containerImage": "${REGISTRY}/acceptance/public-key-param"}]} |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                     |
      | PUBLIC_KEY           | ${known_PUBLIC_KEY}                                                             |
      | IGNORE_REKOR         | true                                                                            |
    Then the task should succeed
      And the task logs for step "report" should match the snapshot
      And the task results should match the snapshot

  # See hack/keyless-test-image for how the quay.io/conforma/test:keyless_v2
  # and quay.io/conforma/test:keyless_v3 test images where created. It's not
  # ideal that this test requires an external image, but we already do this
  # elsewhere, so I guess one more is okay.

  # Todo: We should be able test this also with an internally built image
  # similar to how it's done in the "happy day with keyless" scenario in the
  # validate_image feature.

  # Confirm we can verify the signatures on a keylessly signed image signed with cosign v2
  Scenario: Keyless signing verification cosign v2 style
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release?ref=0de5461c14413484575e63e96ddb514d8ab954b5",
              "github.com/conforma/policy//policy/lib?ref=0de5461c14413484575e63e96ddb514d8ab954b5"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES                  | {"components": [{"containerImage": "quay.io/conforma/test:keyless_v2@sha256:03a10dff06ae364ef9727d562e7077b135b00c7a978e571c4354519e6d0f23b8"}]} |
      | POLICY_CONFIGURATION    | ${NAMESPACE}/${POLICY_NAME}   |
      | CERTIFICATE_IDENTITY    | conformacommunity@gmail.com   |
      | CERTIFICATE_OIDC_ISSUER | https://accounts.google.com   |
      | REKOR_HOST              | https://rekor.sigstore.dev    |
      | IGNORE_REKOR            | false                         |
      | STRICT                  | true                          |
    Then the task should succeed
     And the task logs for step "report-json" should match the snapshot
     And the task results should match the snapshot

  # Confirm we can verify the signatures on a keylessly signed image signed with cosign v3
  Scenario: Keyless signing verification cosign v3 style
    Given a working namespace
    Given a cluster policy with content:
      ```
      {
        "sources": [
          {
            "policy": [
              "github.com/conforma/policy//policy/release?ref=0de5461c14413484575e63e96ddb514d8ab954b5",
              "github.com/conforma/policy//policy/lib?ref=0de5461c14413484575e63e96ddb514d8ab954b5"
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
    When version 0.1 of the task named "verify-enterprise-contract" is run with parameters:
      | IMAGES                  | {"components": [{"containerImage": "quay.io/conforma/test:keyless_v3@sha256:712ca3a7fcd41fe6b3e6f434a31f738743b6c31f1d81ad458502d6b0239a8903"}]} |
      | POLICY_CONFIGURATION    | ${NAMESPACE}/${POLICY_NAME}   |
      | CERTIFICATE_IDENTITY    | conformacommunity@gmail.com   |
      | CERTIFICATE_OIDC_ISSUER | https://accounts.google.com   |
      | REKOR_HOST              | https://rekor.sigstore.dev    |
      | IGNORE_REKOR            | false                         |
      | STRICT                  | true                          |
    Then the task should succeed
     And the task logs for step "report-json" should match the snapshot
     And the task results should match the snapshot

  Scenario: Collect keyless signing parameters from ConfigMap
    Given a working namespace
    And a namespace named "konflux-info" exists
    # Note: These scenarios might run in parallel so let's use a different config map
    # for each scenario so we don't have to worry about them clashing with each other
    And a ConfigMap "cluster-config" in namespace "konflux-info" with content:
      """
      {
        "defaultOIDCIssuer": "https://kubernetes.default.svc.cluster.local",
        "rekorExternalUrl": "https://rekor.example.com",
        "fulcioExternalUrl": "https://fulcio.example.com",
        "tufExternalUrl": "https://tuf.example.com",
        "buildIdentity": "https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller",
        "buildIdentityRegexp": "^https://konflux-ci.dev/.*$",
        "enableKeylessSigning": "true"
      }
      """
    When version 0.1 of the task named "collect-keyless-params" is run with parameters:
      | configMapName      | cluster-config |
    Then the task should succeed
     And the task logs for step "collect-signing-params" should match the snapshot
     And the task result "defaultOIDCIssuer" should equal "https://kubernetes.default.svc.cluster.local"
     And the task result "rekorExternalUrl" should equal "https://rekor.example.com"
     And the task result "fulcioExternalUrl" should equal "https://fulcio.example.com"
     And the task result "tufExternalUrl" should equal "https://tuf.example.com"
     And the task result "buildIdentity" should equal "https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller"
     And the task result "buildIdentityRegexp" should equal "^https://konflux-ci.dev/.*$"
     And the task result "keylessSigningEnabled" should equal "true"

  Scenario: Collect keyless signing parameters from ConfigMap with keyless signing disabled
    Given a working namespace
    And a namespace named "konflux-info" exists
    # Note: These scenarios might run in parallel so let's use a different config map
    # for each scenario so we don't have to worry about them clashing with each other
    And a ConfigMap "cluster-config-2" in namespace "konflux-info" with content:
      """
      {
        "defaultOIDCIssuer": "https://kubernetes.default.svc.cluster.local",
        "rekorExternalUrl": "https://rekor.example.com",
        "fulcioExternalUrl": "https://fulcio.example.com",
        "tufExternalUrl": "https://tuf.example.com",
        "buildIdentity": "https://kubernetes.io/namespaces/openshift-pipelines/serviceaccounts/tekton-chains-controller",
        "buildIdentityRegexp": "^https://konflux-ci.dev/.*$",
        "enableKeylessSigning": "false"
      }
      """
    When version 0.1 of the task named "collect-keyless-params" is run with parameters:
      | configMapName      | cluster-config-2 |
    Then the task should succeed
     And the task logs for step "collect-signing-params" should match the snapshot
     And the task result "defaultOIDCIssuer" should equal ""
     And the task result "rekorExternalUrl" should equal ""
     And the task result "fulcioExternalUrl" should equal ""
     And the task result "tufExternalUrl" should equal ""
     And the task result "buildIdentity" should equal ""
     And the task result "buildIdentityRegexp" should equal ""
     And the task result "keylessSigningEnabled" should equal "false"

  Scenario: Collect keyless signing parameters when there is a malformed ConfigMap
    Given a working namespace
    And a namespace named "konflux-info" exists
    # Note: These scenarios might run in parallel so let's use a different config map
    # for each scenario so we don't have to worry about them clashing with each other
    And a ConfigMap "cluster-config-3" in namespace "konflux-info" with content:
      """
      {"foo": "bar"}
      """
    When version 0.1 of the task named "collect-keyless-params" is run with parameters:
      | configMapName      | cluster-config-3 |
    Then the task should succeed
     And the task logs for step "collect-signing-params" should match the snapshot
     And the task result "defaultOIDCIssuer" should equal ""
     And the task result "rekorExternalUrl" should equal ""
     And the task result "fulcioExternalUrl" should equal ""
     And the task result "tufExternalUrl" should equal ""
     And the task result "buildIdentity" should equal ""
     And the task result "buildIdentityRegexp" should equal ""
     And the task result "keylessSigningEnabled" should equal "false"

  Scenario: Collect keyless signing parameters when the ConfigMap does not exist
    Given a working namespace
    And a namespace named "konflux-info" exists
    # Note: These scenarios might run in parallel so let's use a different config map
    # for each scenario so we don't have to worry about them clashing with each other.
    # Creating a config map deliberately so we are sure the rbac is created. (I might
    # be wrong but I think it could matter if this secenario runs before any of the
    # others.)
    And a ConfigMap "cluster-config-4" in namespace "konflux-info" with content:
      """
      {"foo": "bar"}
      """
    When version 0.1 of the task named "collect-keyless-params" is run with parameters:
      | configMapNamespace | konflux-info |
      | configMapName      | doesnt-exist-config |
    Then the task should succeed
     And the task logs for step "collect-signing-params" should match the snapshot
     And the task result "defaultOIDCIssuer" should equal ""
     And the task result "rekorExternalUrl" should equal ""
     And the task result "fulcioExternalUrl" should equal ""
     And the task result "tufExternalUrl" should equal ""
     And the task result "buildIdentityRegexp" should equal ""
     And the task result "keylessSigningEnabled" should equal "false"

  Scenario: Collect keyless signing parameters when the namespace does not exist
    Given a working namespace
    When version 0.1 of the task named "collect-keyless-params" is run with parameters:
      | configMapNamespace | doesnt-exist-namespace |
      | configMapName      | whatever               |
    Then the task should succeed
     And the task logs for step "collect-signing-params" should match the snapshot
     And the task result "defaultOIDCIssuer" should equal ""
     And the task result "rekorExternalUrl" should equal ""
     And the task result "fulcioExternalUrl" should equal ""
     And the task result "tufExternalUrl" should equal ""
     And the task result "buildIdentity" should equal ""
     And the task result "buildIdentityRegexp" should equal ""
     And the task result "keylessSigningEnabled" should equal "false"
