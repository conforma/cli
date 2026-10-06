Feature: Verify images through the ITS pipeline
  Exercise the repository pipeline with locally built task bundles in kind.

  Background:
    Given a cluster running
      And stub rekord running
      And stub tuf running
      And a working namespace
      And a key pair named "known"
      And a cluster policy with content:
      ```
      {
        "publicKey": ${known_PUBLIC_KEY}
      }
      ```

  Scenario: ITS pipeline validates a signed image
    Given an image named "acceptance/its-signed"
      And a valid image signature of "acceptance/its-signed" image signed by the "known" key
      And a valid attestation of "acceptance/its-signed" signed by the "known" key
    When version 0.1 of the pipeline named "enterprise-contract" is run with parameters:
      | SNAPSHOT             | {"components": [{"containerImage": "${REGISTRY}/acceptance/its-signed"}]} |
      | PUBLIC_KEY           | ${known_PUBLIC_KEY}                                                       |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                               |
    Then the pipeline should succeed
      And the pipeline TEST_OUTPUT should report "SUCCESS"

  Scenario Outline: ITS pipeline handles image lookup failures according to STRICT
    When version 0.1 of the pipeline named "enterprise-contract" is run with parameters:
      | SNAPSHOT             | {"components": [{"containerImage": "${REGISTRY}/acceptance/its-missing"}]} |
      | PUBLIC_KEY           | ${known_PUBLIC_KEY}                                                        |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                |
      | STRICT               | <strict>                                                                   |
    Then the pipeline should <outcome>
      And the pipeline TEST_OUTPUT should report "FAILURE"

    Examples:
      | strict | outcome |
      | true   | fail    |
      | false  | succeed |

  Scenario Outline: ITS pipeline handles untrusted signatures according to STRICT
    Given a key pair named "untrusted"
      And an image named "acceptance/its-untrusted"
      And a valid image signature of "acceptance/its-untrusted" image signed by the "untrusted" key
      And a valid attestation of "acceptance/its-untrusted" signed by the "untrusted" key
    When version 0.1 of the pipeline named "enterprise-contract" is run with parameters:
      | SNAPSHOT             | {"components": [{"containerImage": "${REGISTRY}/acceptance/its-untrusted"}]} |
      | PUBLIC_KEY           | ${known_PUBLIC_KEY}                                                          |
      | POLICY_CONFIGURATION | ${NAMESPACE}/${POLICY_NAME}                                                  |
      | STRICT               | <strict>                                                                     |
    Then the pipeline should <outcome>
      And the pipeline TEST_OUTPUT should report "FAILURE"

    Examples:
      | strict | outcome |
      | true   | fail    |
      | false  | succeed |
