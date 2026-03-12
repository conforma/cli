package referrers

import rego.v1

# METADATA
# custom:
#   short_name: count
deny contains result if {
	refs := ec.oci.image_referrers(input.image.ref)
	count(refs) != 2
	result := {
		"code": "referrers.count",
		"msg": sprintf("Expected 2 referrers, got %d: %v", [count(refs), refs]),
	}
}

# METADATA
# custom:
#   short_name: format
deny contains result if {
	descriptors := ec.oci.image_referrers(input.image.ref)
	not all_descriptors_valid_format(descriptors)
	result := {
		"code": "referrers.format",
		"msg": sprintf("Invalid referrer descriptor format in: %v", [descriptors]),
	}
}

# METADATA
# custom:
#   short_name: content_types
deny contains result if {
	descriptors := ec.oci.image_referrers(input.image.ref)
	not has_expected_artifact_types(descriptors)
	result := {
		"code": "referrers.content_types",
		"msg": sprintf("Expected one signature and one attestation artifact type in referrers: %v", [descriptors]),
	}
}

all_descriptors_valid_format(descriptors) if {
	every descriptor in descriptors {
		# Each descriptor should have required fields
		descriptor.digest != ""
		descriptor.mediaType != ""
		descriptor.size >= 0
		descriptor.artifactType != ""
		descriptor.ref != ""

		# Digest should be a digest-only format: sha256:<hex>
		startswith(descriptor.digest, "sha256:")
		not contains(descriptor.digest, "@")

		# Ref should be a full OCI reference with digest format: registry/repo@sha256:<hex>
		contains(descriptor.ref, "@")
		contains(descriptor.ref, "sha256:")
		# Split by @ and verify format
		parts := split(descriptor.ref, "@")
		count(parts) == 2
		# Verify digest format matches
		parts[1] == descriptor.digest
	}
}

has_expected_artifact_types(descriptors) if {
	# Check that we have one signature artifact directly from descriptors
	signature_artifacts := [d |
		some d in descriptors
		d.artifactType == "application/vnd.dev.cosign.simplesigning.v1+json"
	]
	count(signature_artifacts) == 1

	# Check that we have one attestation artifact directly from descriptors
	attestation_artifacts := [d |
		some d in descriptors
		d.artifactType == "application/vnd.dsse.envelope.v1+json"
	]
	count(attestation_artifacts) == 1
}
