Feature: VSA generation and storage
  The ec command line should generate and store Verification Summary Attestation (VSA)

  Background:
    Given a stub cluster running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running
    Given stub tuf running

  Scenario: VSA generation with local storage backend
    Given a key pair named "vsa-test"
    Given an image named "acceptance/vsa-test-image"
    Given a valid image signature of "acceptance/vsa-test-image" image signed by the "vsa-test" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-test-image"
    Given a valid attestation of "acceptance/vsa-test-image" signed by the "vsa-test" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-test-image"
    Given a git repository named "vsa-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-test-image --policy acceptance/vsa-ec-policy --public-key ${vsa-test_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-test_PRIVATE_KEY} --vsa-upload local@${TMPDIR}/vsa-output --vsa-expiration 0 --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA envelope files should exist in "${TMPDIR}/vsa-output"

  Scenario: VSA generation with Rekor storage backend
    Given a key pair named "vsa-rekor"
    Given an image named "acceptance/vsa-rekor-image"
    Given a valid image signature of "acceptance/vsa-rekor-image" image signed by the "vsa-rekor" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-rekor-image"
    Given a valid attestation of "acceptance/vsa-rekor-image" signed by the "vsa-rekor" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-rekor-image"
    Given a git repository named "vsa-rekor-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-rekor-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-rekor-policy.git"
          ]
        }
      ]
    }
    """
    Given VSA upload to Rekor should be expected
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-rekor-image --policy acceptance/vsa-rekor-ec-policy --public-key ${vsa-rekor_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-rekor_PRIVATE_KEY} --vsa-upload rekor@${REKOR} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA should be uploaded to Rekor successfully

  Scenario: VSA generation with multiple storage backends
    Given a key pair named "vsa-multi"
    Given an image named "acceptance/vsa-multi-image"
    Given a valid image signature of "acceptance/vsa-multi-image" image signed by the "vsa-multi" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-multi-image"
    Given a valid attestation of "acceptance/vsa-multi-image" signed by the "vsa-multi" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-multi-image"
    Given a git repository named "vsa-multi-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-multi-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-multi-policy.git"
          ]
        }
      ]
    }
    """
    Given VSA upload to Rekor should be expected
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-multi-image --policy acceptance/vsa-multi-ec-policy --public-key ${vsa-multi_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-multi_PRIVATE_KEY} --vsa-upload local@${TMPDIR}/vsa-multi-output --vsa-upload rekor@${REKOR} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA envelope files should exist in "${TMPDIR}/vsa-multi-output"
    And VSA should be uploaded to Rekor successfully

  Scenario: VSA generation with invalid storage backend configuration
    Given a key pair named "vsa-invalid"
    Given an image named "acceptance/vsa-invalid-image"
    Given a valid image signature of "acceptance/vsa-invalid-image" image signed by the "vsa-invalid" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-invalid-image"
    Given a valid attestation of "acceptance/vsa-invalid-image" signed by the "vsa-invalid" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-invalid-image"
    Given a git repository named "vsa-invalid-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-invalid-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-invalid-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-invalid-image --policy acceptance/vsa-invalid-ec-policy --public-key ${vsa-invalid_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-invalid_PRIVATE_KEY} --vsa-upload invalid-backend@somewhere --vsa-expiration 0 --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: VSA expiration flag functionality
    Given a key pair named "vsa-expiration"
    Given an image named "acceptance/vsa-expiration-image"
    Given a valid image signature of "acceptance/vsa-expiration-image" image signed by the "vsa-expiration" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-expiration-image"
    Given a valid attestation of "acceptance/vsa-expiration-image" signed by the "vsa-expiration" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-expiration-image"
    Given VSA index search should return no results
    Given a git repository named "vsa-expiration-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-expiration-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-expiration-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-expiration-image@sha256:${REGISTRY_acceptance/vsa-expiration-image:latest_DIGEST} --policy acceptance/vsa-expiration-ec-policy --public-key ${vsa-expiration_PUBLIC_KEY} --rekor-url ${REKOR} --vsa-expiration 1h --vsa-upload rekor@${REKOR} --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: VSA expiration with existing valid VSA
    Given a key pair named "vsa-existing"
    Given an image named "acceptance/vsa-existing-image"
    Given a valid image signature of "acceptance/vsa-existing-image" image signed by the "vsa-existing" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-existing-image"
    Given a valid attestation of "acceptance/vsa-existing-image" signed by the "vsa-existing" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-existing-image"
    Given VSA index search should return valid VSA
    Given a git repository named "vsa-existing-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-existing-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-existing-policy.git"
          ]
        }
      ]
    }
    """
    # First, generate a VSA and upload it to Rekor
    Given VSA upload to Rekor should be expected
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-existing-image@sha256:${REGISTRY_acceptance/vsa-existing-image:latest_DIGEST} --policy acceptance/vsa-existing-ec-policy --public-key ${vsa-existing_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-existing_PRIVATE_KEY} --vsa-upload rekor@${REKOR} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    And VSA should be uploaded to Rekor successfully

    # Then test expiration checking with that existing VSA
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-existing-image@sha256:${REGISTRY_acceptance/vsa-existing-image:latest_DIGEST} --policy acceptance/vsa-existing-ec-policy --public-key ${vsa-existing_PUBLIC_KEY} --rekor-url ${REKOR} --vsa-expiration 24h --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: VSA generation without upload backends shows warning
    Given a key pair named "vsa-no-upload"
    Given an image named "acceptance/vsa-no-upload-image"
    Given a valid image signature of "acceptance/vsa-no-upload-image" image signed by the "vsa-no-upload" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-no-upload-image"
    Given a valid attestation of "acceptance/vsa-no-upload-image" signed by the "vsa-no-upload" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-no-upload-image"
    Given a git repository named "vsa-no-upload-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-no-upload-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-no-upload-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-no-upload-image --policy acceptance/vsa-no-upload-ec-policy --public-key ${vsa-no-upload_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-no-upload_PRIVATE_KEY} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And the log output should contain "[VSA] VSA files generated but not uploaded (no --vsa-upload backends specified)"

  Scenario: VSA upload failure handling
    Given a key pair named "vsa-upload-fail"
    Given an image named "acceptance/vsa-upload-fail-image"
    Given a valid image signature of "acceptance/vsa-upload-fail-image" image signed by the "vsa-upload-fail" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-upload-fail-image"
    Given a valid attestation of "acceptance/vsa-upload-fail-image" signed by the "vsa-upload-fail" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-upload-fail-image"
    Given a git repository named "vsa-upload-fail-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-upload-fail-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-upload-fail-policy.git"
          ]
        }
      ]
    }
    """
    Given Rekor upload should fail
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-upload-fail-image --policy acceptance/vsa-upload-fail-ec-policy --public-key ${vsa-upload-fail_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-upload-fail_PRIVATE_KEY} --vsa-upload rekor@${REKOR} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    And the log output should contain "[VSA] Failed to upload in-toto 0.0.2 entry"
