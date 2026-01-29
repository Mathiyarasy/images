#!/bin/bash

# Check Actionable CVEs for DevContainer Images
# Separates CVEs into actionable (devcontainers can fix) vs upstream (base image)
# Filters out false positives by verifying actual installed versions
# Outputs results in JSON format

set -e

REGISTRY="mcr.microsoft.com/devcontainers"
OUTPUT_DIR="/workspaces/images/scan/cve-reports"
PLATFORM="linux/amd64"

# Images to scan - add more as needed
IMAGES=(
    "anaconda:latest"
    "base:debian"
    "base:ubuntu"
    "base:alpine"
    "cpp:latest"
    "dotnet:latest"
    "go:latest"
    "java:latest"
    "jekyll:latest"
    "miniconda:latest"
    "php:latest"
    "python:latest"
    "ruby:latest"
    "rust:latest"
    "typescript-node:latest"
    "javascript-node:latest"
    "universal:latest"
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

# Get actual installed version of a package from the container
get_actual_version() {
    local image="$1"
    local package="$2"
    local version=""
    
    # Try different package managers and methods
    # 1. dpkg (Debian/Ubuntu)
    version=$(docker run --rm "$image" dpkg -s "$package" 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "")
    
    if [ -z "$version" ]; then
        # 2. rpm (RHEL/Fedora)
        version=$(docker run --rm "$image" rpm -q "$package" 2>/dev/null | sed 's/.*-\([0-9].*\)-.*/\1/' || echo "")
    fi
    
    if [ -z "$version" ]; then
        # 3. apk (Alpine)
        version=$(docker run --rm "$image" apk info "$package" 2>/dev/null | head -1 | sed 's/.*-\([0-9].*\)/\1/' || echo "")
    fi
    
    if [ -z "$version" ]; then
        # 4. Special case for rvm
        if [ "$package" = "rvm" ]; then
            version=$(docker run --rm "$image" bash -c "source /usr/local/rvm/scripts/rvm 2>/dev/null && rvm --version 2>/dev/null | head -1 | awk '{print \$2}'" || echo "")
        fi
    fi
    
    if [ -z "$version" ]; then
        # 5. Try pip for Python packages
        version=$(docker run --rm "$image" pip show "$package" 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "")
    fi
    
    if [ -z "$version" ]; then
        # 6. Try npm for Node packages
        version=$(docker run --rm "$image" npm list -g "$package" 2>/dev/null | grep "$package@" | sed 's/.*@//' || echo "")
    fi
    
    echo "$version"
}

# Compare versions (returns 0 if v1 >= v2)
version_gte() {
    local v1="$1"
    local v2="$2"
    [ "$(printf '%s\n' "$v2" "$v1" | sort -V | head -n1)" = "$v2" ]
}

# Verify CVEs and filter false positives
verify_cves() {
    local image="$1"
    local cves_json="$2"
    local verified_cves="[]"
    local false_positives="[]"
    
    # Parse each CVE and verify
    local count=$(echo "$cves_json" | jq 'length')
    
    for ((i=0; i<count; i++)); do
        local cve=$(echo "$cves_json" | jq -r ".[$i].cve")
        local package=$(echo "$cves_json" | jq -r ".[$i].package")
        local detected_version=$(echo "$cves_json" | jq -r ".[$i].installed_version")
        local fixed_version=$(echo "$cves_json" | jq -r ".[$i].fixed_version")
        local cve_entry=$(echo "$cves_json" | jq ".[$i]")
        
        # Get actual installed version
        local actual_version=$(get_actual_version "$image" "$package")
        
        if [ -n "$actual_version" ]; then
            # Add actual version to the entry
            cve_entry=$(echo "$cve_entry" | jq --arg av "$actual_version" '. + {actual_version: $av}')
            
            # Check if actual version is different from detected
            if [ "$actual_version" != "$detected_version" ]; then
                # Check if actual version >= fixed version (meaning it's patched)
                if version_gte "$actual_version" "$fixed_version"; then
                    # This is a false positive
                    cve_entry=$(echo "$cve_entry" | jq '. + {
                        false_positive: true,
                        reason: "Actual installed version is >= fixed version"
                    }')
                    false_positives=$(echo "$false_positives" | jq --argjson entry "$cve_entry" '. + [$entry]')
                    continue
                fi
            fi
        fi
        
        # Not a false positive, add to verified list
        cve_entry=$(echo "$cve_entry" | jq '. + {false_positive: false}')
        verified_cves=$(echo "$verified_cves" | jq --argjson entry "$cve_entry" '. + [$entry]')
    done
    
    # Return both verified and false positives as JSON object
    jq -n \
        --argjson verified "$verified_cves" \
        --argjson false_positives "$false_positives" \
        '{verified: $verified, false_positives: $false_positives}'
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
                detected_version: ($rule.properties.purls[0] | split("@")[1] | split("?")[0]),
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
                detected_version: ($rule.properties.purls[0] | split("@")[1] | split("?")[0]),
                fixed_version: $rule.properties.fixed_version,
                affected_range: $rule.properties.affected_version,
                description: ($rule.help.text | split("\n")[0])
            }
        ]' 2>/dev/null || echo "[]")
    
    # Verify CVEs and filter false positives
    echo "  Verifying actual installed versions..."
    local actionable_verified=$(verify_cves "$full_image" "$actionable_cves")
    local upstream_verified=$(verify_cves "$full_image" "$upstream_cves")
    
    # Extract verified and false positives
    local actionable_real=$(echo "$actionable_verified" | jq '.verified')
    local actionable_false=$(echo "$actionable_verified" | jq '.false_positives')
    local upstream_real=$(echo "$upstream_verified" | jq '.verified')
    local upstream_false=$(echo "$upstream_verified" | jq '.false_positives')
    
    # Count CVEs
    local actionable_count=$(echo "$actionable_real" | jq 'length')
    local upstream_count=$(echo "$upstream_real" | jq 'length')
    local false_positive_count=$(echo "$actionable_false" | jq 'length')
    local upstream_false_count=$(echo "$upstream_false" | jq 'length')
    local total_false=$((false_positive_count + upstream_false_count))
    
    # Generate combined JSON report
    jq -n \
        --arg image "$full_image" \
        --arg platform "$PLATFORM" \
        --arg scan_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson actionable_count "$actionable_count" \
        --argjson upstream_count "$upstream_count" \
        --argjson false_positive_count "$total_false" \
        --argjson actionable "$actionable_real" \
        --argjson upstream "$upstream_real" \
        --argjson actionable_false "$actionable_false" \
        --argjson upstream_false "$upstream_false" \
        '{
            image: $image,
            platform: $platform,
            scan_date: $scan_date,
            summary: {
                actionable_cve_count: $actionable_count,
                upstream_cve_count: $upstream_count,
                false_positive_count: $false_positive_count,
                total_real_cve_count: ($actionable_count + $upstream_count)
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
            },
            false_positives: {
                description: "CVEs detected by scanner but actual installed version is already fixed",
                count: $false_positive_count,
                actionable: $actionable_false,
                upstream: $upstream_false
            }
        }' > "$output_file"
    
    echo "  ✓ Actionable CVEs: $actionable_count"
    echo "  ✓ Upstream CVEs: $upstream_count"
    echo "  ✓ False positives filtered: $total_false"
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
            total_upstream_cves: (map(.summary.upstream_cve_count) | add),
            total_false_positives: (map(.summary.false_positive_count // 0) | add)
        },
        images: map({
            image: .image,
            actionable_cves: .summary.actionable_cve_count,
            upstream_cves: .summary.upstream_cve_count,
            false_positives: (.summary.false_positive_count // 0)
        })
    }' "${all_reports[@]}" > "$summary_file"
    
    echo "  ✓ Summary saved: $summary_file"
    
    # Print summary to console
    echo ""
    echo "======================================"
    echo "CVE Scan Summary"
    echo "======================================"
    jq -r '.images[] | "  \(.image): \(.actionable_cves) actionable, \(.upstream_cves) upstream, \(.false_positives) false positives"' "$summary_file"
    echo "--------------------------------------"
    jq -r '"  TOTAL: \(.summary.total_actionable_cves) actionable, \(.summary.total_upstream_cves) upstream, \(.summary.total_false_positives) false positives filtered"' "$summary_file"
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
