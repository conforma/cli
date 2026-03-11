#!/bin/bash

# Script to create TUF ConfigMaps with exact file content
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WIREMOCK_TUF_DIR="$PROJECT_ROOT/acceptance/wiremock/recordings/tuf"

# Extract file names from wiremock mapping files
extract_body_files() {
    local files_dir="$WIREMOCK_TUF_DIR/__files"
    local mappings_dir="$WIREMOCK_TUF_DIR/mappings"

    # Check if directories exist
    if [[ ! -d "$files_dir" ]]; then
        echo "Error: WireMock files directory not found: $files_dir" >&2
        exit 1
    fi

    if [[ ! -d "$mappings_dir" ]]; then
        echo "Error: WireMock mappings directory not found: $mappings_dir" >&2
        exit 1
    fi

    local body_files=()

    # Extract bodyFileName from each mapping file using jq
    while IFS= read -r -d '' mapping_file; do
        if [[ -f "$mapping_file" ]]; then
            local body_file
            body_file=$(jq -r '.response.bodyFileName // empty' "$mapping_file")
            if [[ -n "$body_file" && -f "$files_dir/$body_file" ]]; then
                # Skip files that aren't useful for TUF (like root.json which we handle separately)
                if [[ ! "$body_file" =~ root\.json ]]; then
                    body_files+=("$body_file")
                fi
            fi
        fi
    done < <(find "$mappings_dir" -name "mapping-*.json" -print0)

    printf '%s\n' "${body_files[@]}"
}

# Build kubectl command with dynamic file list
build_kubectl_command() {
    local files_dir="$WIREMOCK_TUF_DIR/__files"
    local cmd_args=("kubectl" "create" "configmap" "tuf-files" "--namespace=tuf-service")

    local body_files
    readarray -t body_files < <(extract_body_files)

    if [[ ${#body_files[@]} -eq 0 ]]; then
        echo "Error: No TUF body files found in wiremock recordings" >&2
        exit 1
    fi

    echo "Found ${#body_files[@]} TUF files to include in ConfigMap:" >&2

    for body_file in "${body_files[@]}"; do
        echo "  - $body_file" >&2
        # Use the filename as the key in the ConfigMap
        cmd_args+=("--from-file=$body_file=$files_dir/$body_file")
    done

    cmd_args+=("--dry-run=client" "-o" "yaml" "--validate=false")

    printf '%s\n' "${cmd_args[@]}"
}

# Create ConfigMap YAML files
echo "Creating TUF files ConfigMap YAML..." >&2
readarray -t kubectl_cmd < <(build_kubectl_command)
"${kubectl_cmd[@]}" > "$SCRIPT_DIR/tuf-files-configmap.yaml"

echo "Creating TUF root ConfigMap YAML..." >&2
kubectl create configmap tuf-root-data \
  --namespace=tuf-service \
  --from-file=root.json="$PROJECT_ROOT/acceptance/tuf/root.json" \
  --dry-run=client -o yaml --validate=false > "$SCRIPT_DIR/tuf-root-configmap.yaml"

echo "TUF ConfigMaps YAML files created successfully"
