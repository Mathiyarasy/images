#!/bin/bash

# Enhanced vulnerability scan script using provenance attestations and SBOM filtering
# This script filters out false positives from nested dependencies by:
# 1. Checking provenance attestations to identify the source repository
# 2. Using --ignore-base to filter out CVEs from base images we don't control
# 3. Generating filtered SBOMs to focus on actionable vulnerabilities

set -e

OUTPUT_DIR="/workspaces/images/scan/provenance-reports"
REGISTRY="mcr.microsoft.com/devcontainers"
DEVCONTAINERS_REPO="https://github.com/devcontainers/images"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Define images to scan (same format as pullscan.sh)
IMAGES=(
    "base:debian|linux/amd64"
    # Add more images as needed
)

echo "======================================"
echo "Enhanced Provenance-Based Vulnerability Scan"
echo "======================================"
echo "Registry: $REGISTRY"
echo "Output: $OUTPUT_DIR"
echo "======================================"
echo ""

# Check prerequisites
check_prerequisites() {
    if ! command -v jq &> /dev/null; then
        echo "Installing jq for JSON processing..."
        apt-get update && apt-get install -y jq > /dev/null 2>&1
    fi

    if ! docker scout version &>/dev/null; then
        echo "Error: Docker Scout is not installed. Please install it first."
        echo "Installing Docker Scout..."
        curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
        
        if ! docker scout version &>/dev/null; then
            echo "Error: Failed to install Docker Scout."
            exit 1
        fi
        echo "✓ Docker Scout installed"
        echo ""
    fi
    echo "✓ Prerequisites verified"
}

# Extract provenance information from an image
get_provenance_info() {
    local image="$1"
    local output_file="$2"
    
    echo "Extracting provenance for: $image"
    
    # Get provenance attestation
    local provenance=$(docker buildx imagetools inspect "$image" --format '{{json .Provenance}}' 2>/dev/null || echo "{}")
    
    if [ "$provenance" != "{}" ]; then
        echo "$provenance" | jq '.' > "$output_file"
        
        # Extract key provenance details
        local source_repo=$(echo "$provenance" | jq -r '.["linux/amd64"].SLSA.invocation.environment.github_event_payload.repository.html_url // "unknown"' 2>/dev/null || echo "unknown")
        local materials=$(echo "$provenance" | jq -c '.["linux/amd64"].SLSA.materials // []' 2>/dev/null || echo "[]")
        
        echo "  Source repo: $source_repo"
        echo "  Materials (base images):"
        echo "$materials" | jq -r '.[] | "    - \(.uri)"' 2>/dev/null || echo "    None found"
        
        return 0
    else
        echo "  ⚠️ No provenance attestation found"
        return 1
    fi
}

# Generate SBOM and filter by source
generate_filtered_sbom() {
    local image="$1"
    local output_file="$2"
    
    echo "Generating SBOM for: $image"
    
    # Get full SBOM
    docker scout sbom --format json "$image" 2>/dev/null > "${output_file}.full.json"
    
    # Extract source information
    local source_info=$(jq '.source' "${output_file}.full.json")
    echo "  Source: $(echo "$source_info" | jq -r '.image.name // "unknown"')"
    
    # Get image labels to identify devcontainer ownership
    local labels=$(jq '.source.image.config.config.Labels // {}' "${output_file}.full.json")
    local dev_source=$(echo "$labels" | jq -r '.["dev.containers.source"] // "unknown"')
    
    echo "  Dev containers source label: $dev_source"
    
    # Count packages by type
    echo "  Package summary:"
    jq -r '.artifacts | group_by(.type) | .[] | "    \(.[0].type): \(length) packages"' "${output_file}.full.json" 2>/dev/null || echo "    Unable to summarize"
    
    return 0
}

# Scan for CVEs with layer awareness
scan_with_layer_awareness() {
    local image="$1"
    local platform="$2"
    local output_prefix="$3"
    
    echo ""
    echo "Scanning: $image ($platform)"
    echo "---"
    
    # Pull image first
    echo "Pulling image..."
    docker pull --platform "$platform" "$image" > /dev/null 2>&1 || {
        echo "⚠️ Failed to pull image"
        return 1
    }
    
    # 1. Full scan (all vulnerabilities)
    echo "Running full CVE scan..."
    docker scout cves "$image" \
        --platform "$platform" \
        --only-severity critical,high \
        --only-fixed \
        --format sarif \
        2>/dev/null > "${output_prefix}-full.sarif.json" || true
    
    local full_count=$(jq '.runs[0].results | length // 0' "${output_prefix}-full.sarif.json" 2>/dev/null || echo "0")
    echo "  Total fixable critical/high CVEs: $full_count"
    
    # 2. Scan excluding base image CVEs (actionable for devcontainers team)
    echo "Running scan excluding base image CVEs..."
    docker scout cves "$image" \
        --platform "$platform" \
        --only-severity critical,high \
        --only-fixed \
        --ignore-base \
        --format sarif \
        2>/dev/null > "${output_prefix}-no-base.sarif.json" || true
    
    local no_base_count=$(jq '.runs[0].results | length // 0' "${output_prefix}-no-base.sarif.json" 2>/dev/null || echo "0")
    echo "  Fixable CVEs (excluding base): $no_base_count"
    
    # 3. Scan only base image CVEs (for awareness/upstream tracking)
    echo "Running scan for base image CVEs only..."
    docker scout cves "$image" \
        --platform "$platform" \
        --only-severity critical,high \
        --only-fixed \
        --only-base \
        --format sarif \
        2>/dev/null > "${output_prefix}-base-only.sarif.json" || true
    
    local base_only_count=$(jq '.runs[0].results | length // 0' "${output_prefix}-base-only.sarif.json" 2>/dev/null || echo "0")
    echo "  CVEs from base image only: $base_only_count"
    
    # 4. Scan with location info to identify layer sources
    echo "Running scan with location details..."
    docker scout cves "$image" \
        --platform "$platform" \
        --only-severity critical,high \
        --only-fixed \
        --locations \
        --format json \
        2>/dev/null > "${output_prefix}-with-locations.json" || true
    
    # Generate summary
    {
        echo "# CVE Scan Summary for $image"
        echo "Platform: $platform"
        echo "Scan Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "## Results"
        echo "- Total fixable critical/high CVEs: $full_count"
        echo "- Actionable CVEs (excluding base image): $no_base_count"
        echo "- CVEs inherited from base image: $base_only_count"
        echo ""
        
        if [ "$no_base_count" -gt 0 ]; then
            echo "## Actionable Vulnerabilities (Devcontainers-owned)"
            echo "These CVEs are introduced by devcontainer layers and can be fixed directly:"
            echo ""
            jq -r '.runs[0].results[]? | "- \(.message.text | split("\\n")[0])"' "${output_prefix}-no-base.sarif.json" 2>/dev/null || echo "Unable to parse"
        fi
        
        echo ""
        echo "## Base Image CVEs (For Awareness)"
        echo "These CVEs come from the upstream base image and require upstream fixes:"
        echo ""
        if [ "$base_only_count" -gt 0 ]; then
            jq -r '.runs[0].results[]? | "- \(.message.text | split("\\n")[0])"' "${output_prefix}-base-only.sarif.json" 2>/dev/null || echo "Unable to parse"
        else
            echo "No base image CVEs with available fixes."
        fi
    } > "${output_prefix}-summary.md"
    
    echo ""
    echo "✓ Scan complete. Summary saved to ${output_prefix}-summary.md"
    
    return 0
}

# Compare SBOM materials with provenance
analyze_supply_chain() {
    local image="$1"
    local output_prefix="$2"
    
    echo ""
    echo "Analyzing supply chain for: $image"
    echo "---"
    
    # Get provenance materials (base images used in build)
    local provenance_materials=$(docker buildx imagetools inspect "$image" --format '{{json .Provenance}}' 2>/dev/null | \
        jq -r '.["linux/amd64"].SLSA.materials[]?.uri // empty' 2>/dev/null || echo "")
    
    # Get image config history
    local build_history=$(docker scout sbom --format json "$image" 2>/dev/null | \
        jq '.source.image.config.history[]? | select(.created_by != null) | .created_by' 2>/dev/null || echo "")
    
    {
        echo "# Supply Chain Analysis for $image"
        echo "Analysis Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "## Provenance Materials (Base Images)"
        if [ -n "$provenance_materials" ]; then
            echo "$provenance_materials" | while read -r material; do
                echo "- $material"
            done
        else
            echo "No provenance materials found (image may not have attestations)"
        fi
        echo ""
        echo "## Build Steps"
        echo "Dockerfile commands that created layers:"
        echo '```'
        docker scout sbom --format json "$image" 2>/dev/null | \
            jq -r '.source.image.config.history[]? | select(.empty_layer != true) | .created_by' 2>/dev/null | head -20 || echo "Unable to retrieve"
        echo '```'
        echo ""
        echo "## Image Labels"
        docker scout sbom --format json "$image" 2>/dev/null | \
            jq '.source.image.config.config.Labels' 2>/dev/null || echo "{}"
    } > "${output_prefix}-supply-chain.md"
    
    echo "✓ Supply chain analysis saved to ${output_prefix}-supply-chain.md"
}

# Main execution
main() {
    check_prerequisites
    
    echo ""
    echo "Starting enhanced scans..."
    echo ""
    
    for image_spec in "${IMAGES[@]}"; do
        IFS='|' read -r image_tag platform <<< "$image_spec"
        
        local full_image="${REGISTRY}/${image_tag}"
        local safe_name=$(echo "$image_tag" | tr ':/' '-')
        local output_prefix="${OUTPUT_DIR}/${safe_name}"
        
        echo "======================================"
        echo "Processing: $full_image"
        echo "======================================"
        
        # Get provenance info
        get_provenance_info "$full_image" "${output_prefix}-provenance.json"
        
        # Generate and analyze SBOM
        generate_filtered_sbom "$full_image" "${output_prefix}-sbom"
        
        # Run CVE scans with layer awareness
        scan_with_layer_awareness "$full_image" "$platform" "$output_prefix"
        
        # Analyze supply chain
        analyze_supply_chain "$full_image" "$output_prefix"
        
        echo ""
    done
    
    echo "======================================"
    echo "All scans complete!"
    echo "Reports saved to: $OUTPUT_DIR"
    echo "======================================"
}

main "$@"
