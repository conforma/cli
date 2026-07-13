Feature: inspect ecp
  The ec command line should be able to inspect and merge EnterpriseContractPolicy configurations

  Scenario: inspect single policy file
    Given a file named "base-policy.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/enterprise-contract/ec-release-policy:latest"
    publicKey: "k8s://openshift-pipelines/public-key"
    """
    When ec command is run with "inspect ecp --policy base-policy.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: inspect policy with single overlay
    Given a file named "base-policy.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/enterprise-contract/ec-release-policy:latest"
    publicKey: "k8s://openshift-pipelines/public-key"
    """
    Given a file named "team-overlay.yaml" containing
    """
    exclude:
      - test.rule_data_provided
      - attestation_task_bundle.disallowed_task_reference
    ruleData:
      teamName: platform-team
      customThreshold: 0.95
    """
    When ec command is run with "inspect ecp --policy base-policy.yaml --policy-overlay team-overlay.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: inspect policy with multiple overlays
    Given a file named "base-policy.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/enterprise-contract/ec-release-policy:latest"
    exclude:
      - base_exclude_1
    """
    Given a file named "overlay1.yaml" containing
    """
    exclude:
      - overlay1_exclude
    ruleData:
      key1: value1
    """
    Given a file named "overlay2.yaml" containing
    """
    exclude:
      - overlay2_exclude
    ruleData:
      key2: value2
    """
    When ec command is run with "inspect ecp --policy base-policy.yaml --policy-overlay overlay1.yaml --policy-overlay overlay2.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: arrays are concatenated in overlays
    Given a file named "base.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/example/policy:v1"
    exclude:
      - rule1
      - rule2
    """
    Given a file named "overlay.yaml" containing
    """
    exclude:
      - rule3
      - rule4
    """
    When ec command is run with "inspect ecp --policy base.yaml --policy-overlay overlay.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: overlay values override base values
    Given a file named "base.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/example/policy:v1"
    ruleData:
      baseKey: baseValue
      sharedKey: fromBase
    """
    Given a file named "overlay.yaml" containing
    """
    ruleData:
      overlayKey: overlayValue
      sharedKey: fromOverlay
    """
    When ec command is run with "inspect ecp --policy base.yaml --policy-overlay overlay.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: deep merge of nested ruleData
    Given a file named "base.yaml" containing
    """
    sources:
      - name: Default
        policy:
          - "oci::quay.io/example/policy:v1"
    ruleData:
      level1:
        level2:
          baseKey: baseValue
          sharedKey: fromBase
    """
    Given a file named "overlay.yaml" containing
    """
    ruleData:
      level1:
        level2:
          overlayKey: overlayValue
          sharedKey: fromOverlay
    """
    When ec command is run with "inspect ecp --policy base.yaml --policy-overlay overlay.yaml"
    Then the exit status should be 0
    Then the output should match the snapshot
