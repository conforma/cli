@server
Feature: validate input server mode
  The ec command line should be able to run as a persistent HTTP server
  for policy evaluation

  Background:
    Given stub git daemon running

  Scenario: server mode evaluation with passing policy
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec server is started with "validate input --server --policy git::https://${GITHOST}/git/happy-day-config.git"
    And a POST request is sent to the server at "/v1/validate/input" with body
    """
    {
      "apiVersion": "tekton.dev/v1",
      "kind": "Pipeline",
      "metadata": {"name": "basic-build"},
      "spec": {"tasks": [{"name": "appstudio-init", "taskRef": {"name": "init", "version": "0.1"}}]}
    }
    """
    Then the response status should be 200
    And the response field "success" should be "true"
    And the response header "X-Conforma-Result" should be "pass"
    And the response should match the snapshot

  Scenario: server mode evaluation with violations
    Given a git repository named "multiple-sources-config" with
      | policy.yaml | examples/multiple_sources_config.yaml |
    Given a git repository named "spam-policy" with
      | main.rego | examples/spam.rego |
    Given a git repository named "ham-policy" with
      | main.rego | examples/ham.rego |
    When ec server is started with "validate input --server --policy git::https://${GITHOST}/git/multiple-sources-config.git"
    And a POST request is sent to the server at "/v1/validate/input" with body
    """
    {"spam": false, "ham": "ready"}
    """
    Then the response status should be 200
    And the response field "success" should be "false"
    And the response header "X-Conforma-Result" should be "fail"
    And the response should match the snapshot

  Scenario: server mode health endpoints
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec server is started with "validate input --server --policy git::https://${GITHOST}/git/happy-day-config.git"
    And a GET request is sent to the server at "/live"
    Then the response status should be 200
    And the response should contain "ok"
    And the response should match the snapshot

  Scenario: server mode evaluation with YAML input
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec server is started with "validate input --server --policy git::https://${GITHOST}/git/happy-day-config.git"
    And a POST request is sent to the server at "/v1/validate/input" with content type "application/yaml" and body
    """
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
    Then the response status should be 200
    And the response field "success" should be "true"
    And the response should match the snapshot

  Scenario: server mode invalid input
    Given a git repository named "happy-day-config" with
      | policy.yaml | examples/happy_config.yaml |
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec server is started with "validate input --server --policy git::https://${GITHOST}/git/happy-day-config.git"
    And a POST request is sent to the server at "/v1/validate/input" with body
    """
    not valid json or yaml map
    """
    Then the response status should be 400
    And the response should contain "not valid JSON or YAML"
    And the response should match the snapshot
