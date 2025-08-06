package v1alpha1

import _ "embed"

//go:generate go run -modfile ../../schema/go.mod ../../schema/export.go . github.com/conforma/cli/api/v1alpha1 .
//go:embed policy_spec.json
var Schema string
