Feature: evaluate enterprise contract
  The ec command line should evaluate enterprise contract

  Background:
    Given a stub cluster running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running
    Given stub tuf running

  Scenario: happy day
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with git config and yaml
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | policy.yaml | examples/happy_config.yaml |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with git config and json
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | policy.json | examples/happy_config.json |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with missing git config
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "happy-config" with
      | perlicy.json | examples/happy_config.json |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy git::https://${GITHOST}/git/happy-config.git --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: happy day with keyless
    Given a signed and attested keyless image named "acceptance/ec-happy-day-keyless"
    Given a initialized tuf root
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/keyless.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day-keyless --policy acceptance/ec-policy --certificate-oidc-issuer ${CERT_ISSUER} --certificate-identity ${CERT_IDENTITY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with extra rule data
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --extra-rule-data key=value --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: happy day with invalid extra rule data
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --extra-rule-data key-without-value-1,key-without-value-2 --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: invalid image signature
    Given a key pair named "known"
    Given a key pair named "unknown"
    Given an image named "acceptance/invalid-image-signature"
    Given a valid image signature of "acceptance/invalid-image-signature" image signed by the "known" key
    Given a valid attestation of "acceptance/invalid-image-signature" signed by the "known" key
    Given a git repository named "invalid-image-signature" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "invalid-image-signature-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/invalid-image-signature.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/invalid-image-signature --policy acceptance/invalid-image-signature-policy --public-key ${unknown_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: unexpected image signature cert
    Given a signed and attested keyless image named "acceptance/unexpected-keyless-cert"
    Given a initialized tuf root
    Given a git repository named "unexpected-keyless-cert" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/unexpected-keyless-cert.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/unexpected-keyless-cert --policy acceptance/ec-policy --certificate-oidc-issuer https://spam.cluster.local --certificate-identity https://kubernetes.io/namespaces/bacon/serviceaccounts/eggs --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: inline policy
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/happy-day-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: future failure is converted to a warning
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: future failure is a deny when using effective-date flag
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --effective-time 2100-01-01T12:00:00Z --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: severity is dynamically adjusted
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "dynamic-severity-policy" with
      | main.rego | examples/dynamic_severity.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/dynamic-severity-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json --info"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: multiple policy sources with multiple source groups
    Given a key pair named "known"
    Given an image named "acceptance/ec-multiple-sources"
    Given a valid image signature of "acceptance/ec-multiple-sources" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-multiple-sources" signed by the "known" key
    Given a git repository named "repository1" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "repository2" with
      | main.rego | examples/reject.rego |
    Given a git repository named "repository3" with
      | main.rego | examples/warn.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        { "policy": ["git::https://${GITHOST}/git/repository1.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository2.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository3.git"] }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  #
  # Todo: There is much duplication with the previous scenario. There should
  # be a good way to avoid that, perhaps by introducing a Rule or adding some
  # useful reusable compound steps.
  #
  Scenario: multiple policy sources with one source group
    Given a key pair named "known"
    Given an image named "acceptance/ec-multiple-sources"
    Given a valid image signature of "acceptance/ec-multiple-sources" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-multiple-sources" signed by the "known" key
    Given a git repository named "repository1" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "repository2" with
      | main.rego | examples/reject.rego |
    Given a git repository named "repository3" with
      | main.rego | examples/warn.rego |
    #
    # In this example the result is the same but in this example the there's only one "source
    # group" which means the conftest evaluator is run just once with the three sources fetched
    Given policy configuration named "ec-policy-variation" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/repository1.git",
            "git::https://${GITHOST}/git/repository2.git",
            "git::https://${GITHOST}/git/repository3.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-multiple-sources --policy acceptance/ec-policy-variation --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  # Demonstrate that a validation with no failures, warnings, or successes constitutes a failure as nothing was actually evaluated.
  Scenario: no failures, warnings, or successes
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/allow_all.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1

  # Demonstrate data sources and using the same rules with different data
  Scenario: policy and data sources
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "banana_check" with
      | main.rego | examples/fail_with_data.rego |
    Given a git repository named "banana_data_1" with
      | data.yaml | examples/rule_data_1.yaml |
    Given a git repository named "banana_data_2" with
      | data.yaml | examples/rule_data_2.yaml |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/banana_check.git"
          ],
          "data": [
            "git::https://${GITHOST}/git/banana_data_1.git"
          ]
        },
        {
          "policy": [
            "git::https://${GITHOST}/git/banana_check.git"
          ],
          "data": [
            "git::https://${GITHOST}/git/banana_data_2.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: using attestation time as effective time
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key, patched with
      | [{"op": "add", "path": "/predicate/metadata", "value": {}}, {"op": "add", "path": "/predicate/metadata/buildFinishedOn", "value": "2100-01-01T00:00:00Z"}] |
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --effective-time attestation --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: detailed failures output
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | happy_day.rego | examples/happy_day.rego      |
      | reject.rego    | examples/reject.rego         |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --info --show-successes --output text=${TMPDIR}/output.txt --color --output json"
    Then the exit status should be 1
    Then the output should match the snapshot
    # Throw in some test coverage for `--output text` here
    And the "${TMPDIR}/output.txt" file should match the snapshot

  Scenario: policy rule filtering
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ],
          "config": {
            "include": ["@stamps", "filtering.always_pass"],
            "exclude": ["filtering.always_fail", "filtering.always_fail_with_collection"]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering on imageRef
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "volatileConfig": {
            "exclude": [
              {
                "value": "filtering.always_fail",
                "imageRef": "sha256:${REGISTRY_acceptance/ec-happy-day:latest_DIGEST}"
              },
              {
                "value": "filtering.always_fail_with_collection",
                "imageRef": "sha256:${REGISTRY_acceptance/ec-happy-day:latest_DIGEST}"
              }
            ]
          },
          "config": {
            "include": ["@stamps", "filtering.always_pass", "filtering.always_fail"]
          },
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
     Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering on imageUrl
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "volatileConfig": {
            "exclude": [
              {
                "value": "filtering.always_fail",
                "imageUrl": "${REGISTRY}/acceptance/ec-happy-day"
              },
              {
                "value": "filtering.always_fail_with_collection",
                "imageUrl": "${REGISTRY}/acceptance/ec-happy-day"
              }
            ]
          },
          "config": {
            "include": ["@stamps", "filtering.always_pass", "filtering.always_fail"]
          },
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
     Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering for successes
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ],
          "config": {
            "include": ["@stamps", "filtering.always_pass"],
            "exclude": ["filtering.always_pass_with_collection", "filtering.always_fail_with_collection"]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering per source
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ],
          "config": {
            "include": ["@stamps", "filtering.always_pass"],
            "exclude": ["filtering.always_pass_with_collection", "filtering.always_fail_with_collection"]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: policy rule filtering fails due to inexistent inclusion patterns
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ],
          "config": {
            "include": ["@stamps", "filtering.always_pass", "not-a-rule"],
            "exclude": ["filtering.always_fail", "filtering.always_fail_with_collection"]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: inline application snapshot
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --json-input {"components":[{"name":"Happy","containerImage":"${REGISTRY}/acceptance/ec-happy-day"}]} --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: application snapshot reference
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given an Snapshot named "happy" with specification
    """
    {
      "components": [
        {
          "name": "Happy",
          "containerImage": "${REGISTRY}/acceptance/ec-happy-day"
        }
      ]
    }
    """
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --snapshot acceptance/happy --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: JUnit and AppStudio output format
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "my-policy" with
      | happy_day.rego | examples/happy_day.rego      |
      | reject.rego    | examples/reject.rego         |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output junit"
    Then the exit status should be 1
    Then the output should match the snapshot
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --output appstudio"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: Using OCI bundles
    Given a key pair named "known"
    Given an image named "acceptance/my-image"
    Given a valid image signature of "acceptance/my-image" image signed by the "known" key
    Given a valid attestation of "acceptance/my-image" signed by the "known" key
    Given a OCI policy bundle named "acceptance/happy-day-policy:tag" with
      | main.rego | examples/happy_day.rego |
    Given a OCI policy bundle named "acceptance/allow-all:latest" with
      | main.rego | examples/allow_all.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "oci::https://${REGISTRY}/acceptance/happy-day-policy:tag",
            "oci::${REGISTRY}/acceptance/allow-all:latest"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/my-image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Dropping rego capabilities
    Given a key pair named "known"
    Given an image named "acceptance/ec-happy-day"
    Given a valid image signature of "acceptance/ec-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/ec-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/disallowed_functions.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ec-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: Custom rule data
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "my-policy1" with
      | rule_data.rego | examples/rule_data.rego |
    Given a git repository named "my-policy2" with
      | rule_data.rego | examples/rule_data.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy1.git"
          ],
          "ruleData": {
            "custom": "data1"
          }
        },
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy2.git"
          ],
          "ruleData": {
            "other": "data2"
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --output=json --effective-time 2014-05-31 --show-successes"
    Then the exit status should be 0
    And the output should match the snapshot

  Scenario: mismatched image digest in signature
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given an image named "acceptance/bad-actor" with signature from "acceptance/image"
    Given a valid attestation of "acceptance/bad-actor" signed by the "known" key
    Given a git repository named "mismatched-image-digest" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "mismatched-image-digest" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/mismatched-image-digest.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/bad-actor --policy acceptance/mismatched-image-digest --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: mismatched image digest in attestation
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given an image named "acceptance/bad-actor" with attestation from "acceptance/image"
    Given a valid image signature of "acceptance/bad-actor" image signed by the "known" key
    Given a git repository named "mismatched-image-digest" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "mismatched-image-digest" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/mismatched-image-digest.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/bad-actor --policy acceptance/mismatched-image-digest --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: artifact relocation
    Given a key pair named "known"
    Given an image named "acceptance/source"
    Given a valid image signature of "acceptance/source" image signed by the "known" key
    Given a valid attestation of "acceptance/source" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When all images relating to "acceptance/source" are copied to "acceptance/destination"
    And ec command is run with "validate image --image ${REGISTRY}/acceptance/destination --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: rule dependencies
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "with-dependencies" with
      | main.rego | examples/rules_with_dependencies.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/with-dependencies.git"
          ]
        }
      ]
    }
    """
    And ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: successes are not duplicated
    Given a key pair named "known"
    Given an image named "acceptance/unique-successes"
    Given a valid image signature of "acceptance/unique-successes" image signed by the "known" key
    Given a valid attestation of "acceptance/unique-successes" signed by the "known" key
    Given a git repository named "unique-successes" with
      | happy.rego  | examples/happy_day.rego   |
      | reject.rgo  | examples/reject.rego      |
      | gloomy.rego | examples/gloomy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/unique-successes.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/unique-successes --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --strict=false --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: image config
    Given a key pair named "known"
    Given an image named "acceptance/image-config"
    Given a valid image signature of "acceptance/image-config" image signed by the "known" key
    Given a valid attestation of "acceptance/image-config" signed by the "known" key
    Given a git repository named "image-config-policy" with
      | image_config.rego | examples/image_config.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/image-config-policy.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image-config --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --info --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Output attestations
    Given a key pair named "known"
      And an image named "acceptance/image"
      And a valid image signature of "acceptance/image" image signed by the "known" key
      And a valid attestation of "acceptance/image" signed by the "known" key
      And a git repository named "my-policy" with
      | happy.rego  | examples/happy_day.rego   |
      And policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --output=json --output attestation=${TMPDIR}/attestation.jsonl "
    Then the exit status should be 0
    And the output should match the snapshot
    And the "${TMPDIR}/attestation.jsonl" file should match the snapshot

 Scenario: policy input output
    Given a key pair named "known"
    Given an image named "acceptance/policy-input-output"
    Given a valid image signature of "acceptance/policy-input-output" image signed by the "known" key
    Given a valid attestation of "acceptance/policy-input-output" signed by the "known" key
    Given a git repository named "policy-input-output-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/policy-input-output-policy.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/policy-input-output --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --output policy-input"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: ignore rekor
    Given a key pair named "known"
    Given an image named "acceptance/ignore-rekor"
    Given a valid image signature of "acceptance/ignore-rekor" image signed by the "known" key
    Given a valid attestation of "acceptance/ignore-rekor" signed by the "known" key
    Given a git repository named "ignore-rekor" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/ignore-rekor.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/ignore-rekor --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --ignore-rekor --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: signatures with embedded bundles verify without external rekor queries
    Given a key pair named "known"
    Given an image named "acceptance/rekor-by-default"
    Given a valid image signature of "acceptance/rekor-by-default" image signed by the "known" key
    Given a valid attestation of "acceptance/rekor-by-default" signed by the "known" key
    Given rekor entries are cleared
    Given a git repository named "rekor-by-default" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {"sources": [{"policy": ["git::https://${GITHOST}/git/rekor-by-default.git"]}]}
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/rekor-by-default --rekor-url ${REKOR} --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: OLM manifests
    Given a key pair named "known"
      And an image named "acceptance/image" containing a layer with:
      | manifests/some.crd.yaml                   | examples/some.crd.yaml                   |
      | manifests/some.clusterserviceversion.yaml | examples/some.clusterserviceversion.yaml |
      And the image "acceptance/image" has labels:
      | operators.operatorframework.io.bundle.manifests.v1 | manifests/ |
      And a valid image signature of "acceptance/image" image signed by the "known" key
      And a valid attestation of "acceptance/image" signed by the "known" key
      And a git repository named "olm-manifests" with
      | image_config.rego | examples/olm_manifests.rego |
      And policy configuration named "policy" with specification
      """
      {"sources": [{"policy": ["git::https://${GITHOST}/git/olm-manifests.git"]}]}
      """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/policy --public-key ${known_PUBLIC_KEY} --ignore-rekor --show-successes  --output=json --output=policy-input=${TMPDIR}/input.json"
    Then the exit status should be 0
     And the output should match the snapshot
     And the "${TMPDIR}/input.json" file should match the snapshot

  Scenario: volatile config warnings schema contract
    Given a key pair named "known"
    Given an image named "acceptance/volatile-config-test"
    Given a valid image signature of "acceptance/volatile-config-test" image signed by the "known" key
    Given a valid attestation of "acceptance/volatile-config-test" signed by the "known" key
    Given a git repository named "volatile-config-policy" with
      | main.rego | examples/volatile_config_warnings.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "name": "volatile-test-source",
          "policy": [
            "git::https://${GITHOST}/git/volatile-config-policy.git"
          ],
          "volatileConfig": {
            "exclude": [
              {
                "value": "test.rule_with_no_expiration"
              },
              {
                "value": "test.rule_expiring_soon",
                "effectiveUntil": "2099-12-31T23:59:59Z"
              },
              {
                "value": "test.rule_pending_activation",
                "effectiveOn": "2099-01-01T00:00:00Z"
              },
              {
                "value": "test.component_scoped_rule",
                "componentNames": ["Unnamed"]
              }
            ]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/volatile-config-test --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --ignore-rekor --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: Unsupported policies
    Given a key pair named "known"
    Given an image named "acceptance/image"
    Given a valid image signature of "acceptance/image" image signed by the "known" key
    Given a valid attestation of "acceptance/image" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/unsupported.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --ignore-rekor --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: fetch OCI blob
    Given a key pair named "known"
    Given an image named "acceptance/fetch-oci-blob"
    Given a valid image signature of "acceptance/fetch-oci-blob" image signed by the "known" key
    Given a valid attestation of "acceptance/fetch-oci-blob" signed by the "known" key
    Given an OCI blob with content "spam" in the repo "acceptance/fetch-oci-blob"
    Given a git repository named "fetch-oci-blob-policy" with
      | main.rego | examples/fetch_blob.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/fetch-oci-blob-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/fetch-oci-blob --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: fetch OCI image manifest
    Given a key pair named "known"
    Given an image named "acceptance/oci-image-manifest"
    Given a valid image signature of "acceptance/oci-image-manifest" image signed by the "known" key
    Given a valid attestation of "acceptance/oci-image-manifest" signed by the "known" key
    Given a git repository named "oci-image-manifest-policy" with
      | main.rego | examples/oci_image_manifest.rego |
    Given policy configuration named "ec-policy" with specification
      """
      {
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/oci-image-manifest-policy"
            ]
          }
        ]
      }
      """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/oci-image-manifest --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: fetch OCI image files
    Given a key pair named "known"
    Given an image named "acceptance/oci-image-files" containing a layer with:
      | manifests/some.crd.yaml                   | examples/some.crd.yaml                   |
      | manifests/some.clusterserviceversion.yaml | examples/some.clusterserviceversion.yaml |
    Given a valid image signature of "acceptance/oci-image-files" image signed by the "known" key
    Given a valid attestation of "acceptance/oci-image-files" signed by the "known" key
    Given a git repository named "oci-image-files-policy" with
      | main.rego | examples/oci_image_files.rego |
    Given policy configuration named "ec-policy" with specification
      """
      {
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/oci-image-files-policy"
            ]
          }
        ]
      }
      """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/oci-image-files --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: tracing and debug logging
    Given a key pair named "trace_debug"
      And an image named "acceptance/trace-debug"
      And a valid image signature of "acceptance/trace-debug" image signed by the "trace_debug" key
      And a valid attestation of "acceptance/trace-debug" signed by the "trace_debug" key
      And a git repository named "trace-debug" with
      | main.rego | examples/trace_debug.rego |
      And policy configuration named "ec-policy" with specification
      """
      {
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/trace-debug.git"
            ]
          }
        ]
      }
      """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/trace-debug --policy acceptance/ec-policy --public-key ${trace_debug_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json --trace=opa"
    Then the exit status should be 0
     And the standard error should contain
      """
      level=trace msg="\[data.main.deny\] Enter data.main.deny
      """
     And the standard error should contain
      """
      level=debug msg="\[data.main.deny\] .*/main.rego:12: here we are
      """

  Scenario: PURL functions
    Given a key pair named "known"
    Given an image named "acceptance/purl"
    Given a valid image signature of "acceptance/purl" image signed by the "known" key
    Given a valid attestation of "acceptance/purl" signed by the "known" key
    Given an OCI blob with content "spam" in the repo "acceptance/purl"
    Given a git repository named "purl-policy" with
      | main.rego | examples/purl.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/purl-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/purl --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: sigstore functions
    Given a key pair named "known"
    Given an image named "acceptance/sigstore"
    Given a valid image signature of "acceptance/sigstore" image signed by the "known" key
    Given a valid attestation of "acceptance/sigstore" signed by the "known" key
    Given a git repository named "sigstore" with
      | main.rego | examples/sigstore.rego |
    Given policy configuration named "ec-policy" with specification
      """
      {
        "sources": [
          {
            "policy": [
              "git::https://${GITHOST}/git/sigstore.git"
            ]
          }
        ]
      }
      """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/sigstore --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  # Commented out as part of EC-1023. This will be enabled once the issue is resolved.
  # Scenario: many components and sources
  #   Given a key pair named "known"
  #     And a git repository named "multitude-policy" with
  #     | main.rego | examples/happy_day.rego |
  #     And policy configuration named "ec-policy" with 10 policy sources from "git::https://${GITHOST}/git/multitude-policy.git", patched with
  #     | [{"op": "add", "path": "/sources/0/ruleData", "value": {"key": "value"}}]      |
  #     | [{"op": "add", "path": "/sources/1/ruleData", "value": {"something": "here"}}] |
  #     | [{"op": "add", "path": "/sources/2/ruleData", "value": {"key": "different"}}]  |
  #     | [{"op": "add", "path": "/sources/3/ruleData", "value": {"hello": "world"}}]    |
  #     | [{"op": "add", "path": "/sources/4/ruleData", "value": {"foo": "bar"}}]        |
  #     | [{"op": "add", "path": "/sources/5/ruleData", "value": {"peek": "poke"}}]      |
  #     | [{"op": "add", "path": "/sources/6/ruleData", "value": {"hide": "seek"}}]      |
  #     | [{"op": "add", "path": "/sources/7/ruleData", "value": {"hokus": "pokus"}}]    |
  #     | [{"op": "add", "path": "/sources/8/ruleData", "value": {"mr": "mxyzptlk"}}]    |
  #     | [{"op": "add", "path": "/sources/9/ruleData", "value": {"more": "data"}}]      |
  #     And an Snapshot named "multitude" with 10 components signed with "known" key
  #   When ec command is run with "validate image --snapshot acceptance/multitude --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
  #   Then the exit status should be 0
  #    And the output should match the snapshot

  Scenario: Format options
    Given a key pair named "known"
      And an image named "acceptance/image"
      And a valid image signature of "acceptance/image" image signed by the "known" key
      And a valid attestation of "acceptance/image" signed by the "known" key
      And a git repository named "my-policy" with
      | happy_day.rego | examples/happy_day.rego      |
      | reject.rego    | examples/reject.rego         |
      And policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/my-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/image --policy acceptance/ec-policy --rekor-url ${REKOR} --public-key ${known_PUBLIC_KEY} --output text?show-successes=false --output json=${TMPDIR}/output.json --show-successes"
    Then the exit status should be 1
     And the output should match the snapshot
     And the "${TMPDIR}/output.json" file should match the snapshot

  Scenario: SLSA v1 attestation support
    Given a key pair named "known"
      And an image named "acceptance/slsa-v1-test"
      And a valid image signature of "acceptance/slsa-v1-test" image signed by the "known" key
      And a valid slsa v1 attestation of "acceptance/slsa-v1-test" signed by the "known" key
      And a git repository named "sigstore-v1-policy" with
      | main.rego | examples/sigstore.rego |
      And policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/sigstore-v1-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/slsa-v1-test --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    And the output should match the snapshot
