package main

import (
	"encoding/json"
	"testing"

	v1alpha1 "github.com/conforma/cli/api/v1alpha1"
	"github.com/santhosh-tekuri/jsonschema/v5"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestJsonAdditionalProperties(t *testing.T) {
	schema, err := jsonschema.CompileString("schema.json", v1alpha1.Schema)
	if err != nil {
		t.Errorf("unable to compile the schema for v1alpha1: %v", err)
	}

	ruleData := []byte(`{"any": "value"}`)

	policy := v1alpha1.EnterpriseContractPolicySpec{
		Sources: []v1alpha1.Source{
			{
				RuleData: &v1.JSON{
					Raw: ruleData,
				},
			},
		},
	}

	j, err := json.Marshal(policy)
	if err != nil {
		t.Errorf("unable to marshal policy to JSON: %v", err)
	}

	val := map[string]any{}
	if err := json.Unmarshal(j, &val); err != nil {
		t.Errorf("unable to unmarshal JSON: %v", err)
	}

	if err := schema.Validate(val); err != nil {
		t.Errorf("schema validation should pass, but it failed with: %v", err)
	}
}
