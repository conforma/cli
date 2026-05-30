Feature: embedded rego functionality
  The ec command should be able to use embedded rego functions in policy evaluation

  Background:
    # Todo: We can use file paths so we don't really need git to test this
    Given stub git daemon running

  Scenario: policy using embedded rego functions
    Given a git repository named "embedded-rego-config" with
      | policy.yaml | examples/embedded_rego_config.yaml |
    Given a git repository named "embedded-rego-policy" with
      | main.rego | examples/embedded_rego_test.rego |

    # The rego in embedded_rego_test ignores the input
    Given a pipeline definition file named "pipeline_definition.json" containing
    """
    {}
    """

    When ec command is run with "validate input --file pipeline_definition.json --policy git::https://${GITHOST}/git/embedded-rego-config.git --show-successes"
    Then the exit status should be 1
    Then the output should match the snapshot
