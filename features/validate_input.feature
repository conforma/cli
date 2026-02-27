Feature: validate input
  The ec command line should be able to inspect input files

  Background:
    Given stub git daemon running

  Scenario: valid policy URL
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-config.git --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  # Test for issue #1528: ec validate input should work when policy has publicKey
  Scenario: valid policy URL with publicKey in policy config
    Given a git repository named "happy-day-config-with-public-key" with
      | policy.yaml | examples/happy_config_with_public_key.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-config-with-public-key.git --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: valid policy URL with text output
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/happy-day-config.git --output text --show-successes --color"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy URL with no rego files
    Given a git repository named "sad-day-config" with
      | policy.yaml | examples/sad_config.yaml |
    Given a git repository named "sad-day-policy" with
      | main.reg0 | examples/happy_day.rego |
    Given a pipeline definition file named "pipeline_definition.yaml" containing
    """
    ---
    apiVersion: tekton.dev/v1
    kind: Pipeline
    metadata:
      name: basic-build
    spec:
      tasks:
      - name: appstudio-init
        taskRef:
          name: init
          version: "0.1"
    """
    When ec command is run with "validate input --file pipeline_definition.yaml --policy git::https://${GITHOST}/git/sad-day-config.git --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: policy with multiple sources
    Given a git repository named "multiple-sources-config" with
      | policy.yaml | examples/multiple_sources_config.yaml |
    Given a git repository named "spam-policy" with
      | main.rego | examples/spam.rego |
    Given a git repository named "ham-policy" with
      | main.rego | examples/ham.rego |
    Given a pipeline definition file named "input.yaml" containing
      """
      ---
      spam: false
      ham: rotten
      """
    When ec command is run with "validate input --file input.yaml --policy git::https://${GITHOST}/git/multiple-sources-config.git --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  # In this example the same top level key is defined in
  # two different data sources, but its value a map.
  # In this situation a merge happens and we get second
  # level keys from both sources.
  Scenario: multiple data source top level key map merging
    Given a file named "policy.yaml" containing
      """
      sources:
        - data:
            - "file::acceptance/examples/data-merges/data-1"
            - "file::acceptance/examples/data-merges/data-2"
          policy:
            - "file::acceptance/examples/data-merges/policy"
      """
    Given a file named "input.json" containing
      """
      {}
      """
    When ec command is run with "validate input --file input.json --policy policy.yaml -o yaml"
    Then the exit status should be 0
    Then the output should match the snapshot

  # In this example the same top level key is defined in
  # two different data sources, but its value is not a map.
  # In this situation ec throws a "merge error" error.
  Scenario: multiple data source top level key clash
    Given a file named "policy.yaml" containing
      """
      sources:
        - data:
            - "file::acceptance/examples/data-merges/data-3"
            - "file::acceptance/examples/data-merges/data-4"
          policy:
            - "file::acceptance/examples/data-merges/policy"
      """
    Given a file named "input.json" containing
      """
      {}
      """
    When ec command is run with "validate input --file input.json --policy policy.yaml -o yaml"
    Then the exit status should be 1
    Then the output should match the snapshot
