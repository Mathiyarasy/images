#!/bin/bash

# Check Actionable CVEs for DevContainer Images
# Separates CVEs into actionable (devcontainers can fix) vs upstream (base image)
# Outputs results in JSON format

set -e

REGISTRY="mcr.microsoft.com/devcontainers"
OUTPUT_DIR="/workspaces/images/scan/cve-reports"
PLATFORM="linux/amd64"

# Images to scan - add more as needed
IMAGES=(
    "base:debian"
    "base:ubuntu"
    # "typescript-node:latest"
    # "python:latest"
    # "javascript-node:latest"
)

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check if Docker Scout is installed
check_prerequisites() {
    if ! docker scout version &>/dev/null; then
        echo "Docker Scout is not installed."
        exit 1
    fi
    
    if ! command -v jq &>/dev/null; then
        echo "Installing jq..."
        apt-get update && apt-get install -y jq > /dev/null 2>&1
    fi
    
    echo "✓ Prerequisites verified"
}

# Scan a single image and generate JSON report
scan_image() {
    local image_tag="$1"
    local full_image="${REGISTRY}/${image_tag}"
    local safe_name=$(echo "$image_tag" | tr ':/' '-')
    local output_file="${OUTPUT_DIR}/${safe_name}-cve-report.json"
    
    echo ""
    echo "Scanning: $full_image"
    echo "---"
    
    # Pull image
    echo "  Pulling image..."
    if ! docker pull --platform "$PLATFORM" "$full_image" > /dev/null 2>&1; then
        echo "  ✗ Failed to pull image"
        return 1
    fi
    
    # Get actionable CVEs (excluding base image) - using SARIF format
    echo "  Scanning for actionable CVEs..."
    local actionable_sarif=$(docker scout cves "$full_image" \
        --platform "$PLATFORM" \
        --only-severity critical,high \
        --only-fixed \
        --ignore-base \
        --format sarif 2>/dev/null || echo '{"runs":[{"results":[],"tool":{"driver":{"rules":[]}}}]}')
    
    # Get upstream/base image CVEs
    echo "  Scanning for upstream CVEs..."
    local upstream_sarif=$(docker scout cves "$full_image" \
        --platform "$PLATFORM" \
        --only-severity critical,high \
        --only-fixed \
        --only-base \
        --format sarif 2>/dev/null || echo '{"runs":[{"results":[],"tool":{"driver":{"rules":[]}}}]}')
    
    # Count CVEs from SARIF format
    local actionable_count=$(echo "$actionable_sarif" | jq '.runs[0].results | length' 2>/dev/null || echo "0")
    local upstream_count=$(echo "$upstream_sarif" | jq '.runs[0].results | length' 2>/dev/null || echo "0")
    
    # Extract CVE details from SARIF format - join results with rules for full details
    local actionable_cves=$(echo "$actionable_sarif" | jq '
        .runs[0] as $run |
        [$run.results[]? | . as $result |
            ($run.tool.driver.rules[] | select(.id == $result.ruleId)) as $rule |
            {
                cve: $result.ruleId,
                severity: $rule.properties.cvssV3_severity,
                cvss_score: $rule.properties."security-severity",
                package: ($rule.properties.purls[0] | split("@")[0] | split("/")[-1]),
                installed_version: ($rule.properties.purls[0] | split("@")[1] | split("?")[0]),
                fixed_version: $rule.properties.fixed_version,
                affected_range: $rule.properties.affected_version,
                description: ($rule.help.text | split("\n")[0])
            }
        ]' 2>/dev/null || echo "[]")
    
    local upstream_cves=$(echo "$upstream_sarif" | jq '
        .runs[0] as $run |
        [$run.results[]? | . as $result |
            ($run.tool.driver.rules[] | select(.id == $result.ruleId)) as $rule |
            {
                cve: $result.ruleId,
                severity: $rule.properties.cvssV3_severity,
                cvss_score: $rule.properties."security-severity",
                package: ($rule.properties.purls[0] | split("@")[0] | split("/")[-1]),
                installed_version: ($rule.properties.purls[0] | split("@")[1] | split("?")[0]),
                fixed_version: $rule.properties.fixed_version,
                affected_range: $rule.properties.affected_version,
                description: ($rule.help.text | split("\n")[0])
            }
        ]' 2>/dev/null || echo "[]")
    
    # Generate combined JSON report
    jq -n \
        --arg image "$full_image" \
        --arg platform "$PLATFORM" \
        --arg scan_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson actionable_count "$actionable_count" \
        --argjson upstream_count "$upstream_count" \
        --argjson actionable "$actionable_cves" \
        --argjson upstream "$upstream_cves" \
        '{
            image: $image,
            platform: $platform,
            scan_date: $scan_date,
            summary: {
                actionable_cve_count: $actionable_count,
                upstream_cve_count: $upstream_count,
                total_cve_count: ($actionable_count + $upstream_count)
            },
            actionable_cves: {
                description: "CVEs that the devcontainers team can fix directly",
                count: $actionable_count,
                cves: $actionable
            },
            upstream_cves: {
                description: "CVEs from base image - requires upstream fix",
                count: $upstream_count,
                cves: $upstream
            }
        }' > "$output_file"
    
    echo "  ✓ Actionable CVEs: $actionable_count"
    echo "  ✓ Upstream CVEs: $upstream_count"
    echo "  ✓ Report saved: $output_file"
    
    return 0
}

# Generate combined summary report
generate_summary() {
    local summary_file="${OUTPUT_DIR}/summary.json"
    
    echo ""
    echo "Generating summary report..."
    
    # Combine all individual reports into a summary
    local all_reports=()
    for report in "${OUTPUT_DIR}"/*-cve-report.json; do
        if [ -f "$report" ]; then
            all_reports+=("$report")
        fi
    done
    
    if [ ${#all_reports[@]} -eq 0 ]; then
        echo "  No reports found"
        return 1
    fi
    
    # Create summary JSON
    jq -s '{
        scan_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        total_images_scanned: length,
        summary: {
            total_actionable_cves: (map(.summary.actionable_cve_count) | add),
            total_upstream_cves: (map(.summary.upstream_cve_count) | add)
        },
        images: map({
            image: .image,
            actionable_cves: .summary.actionable_cve_count,
            upstream_cves: .summary.upstream_cve_count
        })
    }' "${all_reports[@]}" > "$summary_file"
    
    echo "  ✓ Summary saved: $summary_file"
    
    # Print summary to console
    echo ""
    echo "======================================"
    echo "CVE Scan Summary"
    echo "======================================"
    jq -r '.images[] | "  \(.image): \(.actionable_cves) actionable, \(.upstream_cves) upstream"' "$summary_file"
    echo "--------------------------------------"
    jq -r '"  TOTAL: \(.summary.total_actionable_cves) actionable, \(.summary.total_upstream_cves) upstream"' "$summary_file"
    echo "======================================"
}

main() {
    echo "======================================"
    echo "DevContainer Actionable CVE Scanner"
    echo "======================================"
    echo "Registry: $REGISTRY"
    echo "Output: $OUTPUT_DIR"
    echo "======================================"
    
    check_prerequisites
    
    # Scan each image
    for image_tag in "${IMAGES[@]}"; do
        scan_image "$image_tag"
    done
    
    # Generate summary
    generate_summary
    
    echo ""
    echo "Done! Reports available in: $OUTPUT_DIR"
}

main "$@"
