package tag_refs

import rego.v1

# METADATA
# custom:
#   short_name: count
deny contains result if {
	refs := ec.oci.image_tag_refs(input.image.ref)
	count(refs) != 2
	result := {
		"code": "tag_refs.count",
		"msg": sprintf("Expected 2 tag-based artifact references, got %d: %v", [count(refs), refs]),
	}
}

# METADATA
# custom:
#   short_name: format
deny contains result if {
	refs := ec.oci.image_tag_refs(input.image.ref)
	not all_refs_valid_format(refs)
	result := {
		"code": "tag_refs.format",
		"msg": sprintf("Invalid tag reference format in: %v", [refs]),
	}
}

# METADATA
# custom:
#   short_name: sig_count
deny contains result if {
	refs := ec.oci.image_tag_refs(input.image.ref)
	sig_count := count([ref | some ref in refs; contains(ref, ".sig")])
	sig_count != 1
	result := {
		"code": "tag_refs.sig_count",
		"msg": sprintf("Expected 1 .sig reference, got %d", [sig_count]),
	}
}

# METADATA
# custom:
#   short_name: att_count
deny contains result if {
	refs := ec.oci.image_tag_refs(input.image.ref)
	att_count := count([ref | some ref in refs; contains(ref, ".att")])
	att_count != 1
	result := {
		"code": "tag_refs.att_count",
		"msg": sprintf("Expected 1 .att reference, got %d", [att_count]),
	}
}

all_refs_valid_format(refs) if {
	every ref in refs {
		# Each ref should be a valid OCI reference with tag format: registry/repo:sha256-<hex>.<suffix>
		contains(ref, ":")
		contains(ref, "sha256-")
		# Split by : and get the last part (the tag)
		parts := split(ref, ":")
		tag_part := parts[count(parts) - 1]
		# Tag should start with sha256- and end with .sig or .att
		startswith(tag_part, "sha256-")
		valid_suffix(tag_part)
	}
}

valid_suffix(tag) if {
	endswith(tag, ".sig")
}

valid_suffix(tag) if {
	endswith(tag, ".att")
}
