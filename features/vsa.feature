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
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-existing-image@sha256:${REGISTRY_acceptance/vsa-existing-image:latest_DIGEST} --policy acceptance/vsa-existing-ec-policy --public-key ${vsa-existing_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-existing_PRIVATE_KEY} --vsa-upload rekor@${REKOR} --vsa-expiration 0 --output json"
    Then the exit status should be 0
    And VSA should be uploaded to Rekor successfully

    # Then test expiration checking with that existing VSA
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-existing-image@sha256:${REGISTRY_acceptance/vsa-existing-image:latest_DIGEST} --policy acceptance/vsa-existing-ec-policy --public-key ${vsa-existing_PUBLIC_KEY} --rekor-url ${REKOR} --vsa-expiration 24h --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
