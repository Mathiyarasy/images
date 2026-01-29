#!/bin/bash

# SBOM-Based Vulnerability Filtering Script
# Filters false positives by cross-referencing SBOM data with actual installed versions
# and provides detailed package location information
#
# Features:
# - Generates SBOM from container images
# - Cross-references CVEs with actual installed package versions
# - Identifies package locations (layer, path, package manager)
# - Maintains an allowlist for known false positives
# - Outputs filtered, actionable vulnerability report

set -e

# Configuration
REGISTRY="${REGISTRY:-mcr.microsoft.com/devcontainers}"
OUTPUT_DIR="/workspaces/images/scan/sbom-reports"
ALLOWLIST_FILE="/workspaces/images/scan/sbom-allowlist.json"
PLATFORM="${PLATFORM:-linux/amd64}"
SEVERITY_FILTER="${SEVERITY_FILTER:-critical,high}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Create default allowlist if it doesn't exist
create_default_allowlist() {
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        cat > "$ALLOWLIST_FILE" << 'EOF'
{
  "description": "Allowlist for known false positives in Docker Scout vulnerability scans",
  "last_updated": "2026-01-29",
  "entries": [
    {
      "cve": "EXAMPLE-CVE-2024-0001",
      "package": "example-package",
      "reason": "False positive - package is not actually installed or version mismatch",
      "expires": "2026-12-31",
      "added_by": "auto-generated"
    }
  ],
  "global_ignores": {
    "packages": [],
    "cve_patterns": []
  }
}
EOF
        echo -e "${YELLOW}Created default allowlist at: $ALLOWLIST_FILE${NC}"
    fi
}

# Check prerequisites
check_prerequisites() {
    echo "======================================"
    echo "SBOM-Based Vulnerability Filter"
    echo "======================================"
    
    # Check jq
    if ! command -v jq &>/dev/null; then
        echo "Installing jq..."
        apt-get update && apt-get install -y jq > /dev/null 2>&1
    fi
    
    # Check Docker Scout
    if ! docker scout version &>/dev/null; then
        echo -e "${YELLOW}Docker Scout not installed. Installing...${NC}"
        curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
        
        if ! docker scout version &>/dev/null; then
            echo -e "${RED}Failed to install Docker Scout${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ Prerequisites verified${NC}"
    echo ""
}

# Generate SBOM for an image
generate_sbom() {
    local image="$1"
    local output_file="$2"
    
    echo -e "${BLUE}Generating SBOM for: $image${NC}"
    
    # Generate JSON SBOM (spdx format requires different flag in newer versions)
    if ! docker scout sbom "$image" \
        --platform "$PLATFORM" \
        --format json \
        --output "$output_file" 2>&1; then
        echo -e "${YELLOW}Warning: SBOM generation had issues, continuing...${NC}"
    fi
    
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        echo -e "${GREEN}✓ SBOM generated: $output_file${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ SBOM file empty or missing, creating placeholder${NC}"
        echo '{"packages":[]}' > "$output_file"
        return 0
    fi
}

# Extract package information from SBOM with locations
extract_packages_with_locations() {
    local sbom_file="$1"
    
    # Parse SPDX SBOM and extract package info with locations
    jq '
    [.packages[]? | select(.SPDXID != "SPDXRef-DOCUMENT") | {
        name: .name,
        version: .versionInfo,
        purl: (.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator),
        supplier: .supplier,
        download_location: .downloadLocation,
        files_analyzed: .filesAnalyzed,
        source_info: .sourceInfo,
        annotations: .annotations
    }]' "$sbom_file" 2>/dev/null || echo "[]"
}

# Get actual installed version using multiple methods
get_actual_installed_version() {
    local image="$1"
    local package="$2"
    local pkg_type="$3"
    
    local version=""
    
    case "$pkg_type" in
        "deb"|"debian")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                dpkg-query -W -f='${Version}' "$package" 2>/dev/null || echo "")
            ;;
        "rpm"|"redhat")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                rpm -q --qf '%{VERSION}-%{RELEASE}' "$package" 2>/dev/null || echo "")
            ;;
        "apk"|"alpine")
            # apk info -v returns "package-version", extract just the version part
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                apk list -I "$package" 2>/dev/null | head -1 | awk '{print $1}' | sed "s/^${package}-//" || echo "")
            ;;
        "npm"|"node")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                npm list -g "$package" --depth=0 2>/dev/null | grep "$package@" | sed 's/.*@//' || echo "")
            ;;
        "pip"|"pypi"|"python")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                pip show "$package" 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "")
            ;;
        "gem"|"ruby")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                gem list "^${package}$" --local 2>/dev/null | grep "$package" | sed 's/.*(\(.*\))/\1/' || echo "")
            ;;
        "go"|"golang")
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo "")
            ;;
        *)
            # Try auto-detection in order: dpkg -> apk -> rpm -> pip -> npm
            version=$(docker run --rm --platform "$PLATFORM" "$image" \
                dpkg-query -W -f='${Version}' "$package" 2>/dev/null || echo "")
            
            if [ -z "$version" ]; then
                version=$(docker run --rm --platform "$PLATFORM" "$image" \
                    apk info -v "$package" 2>/dev/null | head -1 | sed 's/.*-\([0-9].*\)/\1/' || echo "")
            fi
            
            if [ -z "$version" ]; then
                version=$(docker run --rm --platform "$PLATFORM" "$image" \
                    pip show "$package" 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "")
            fi
            ;;
    esac
    
    echo "$version"
}

# Find package location in the filesystem
find_package_location() {
    local image="$1"
    local package="$2"
    local pkg_type="$3"
    
    local locations=""
    
    case "$pkg_type" in
        "deb"|"debian")
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                dpkg -L "$package" 2>/dev/null | head -20 | tr '\n' ',' | sed 's/,$//' || echo "")
            ;;
        "rpm"|"redhat")
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                rpm -ql "$package" 2>/dev/null | head -20 | tr '\n' ',' | sed 's/,$//' || echo "")
            ;;
        "apk"|"alpine")
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                apk info -L "$package" 2>/dev/null | head -20 | tr '\n' ',' | sed 's/,$//' || echo "")
            ;;
        "npm"|"node")
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                npm root -g 2>/dev/null || echo "/usr/local/lib/node_modules")
            locations="${locations}/${package}"
            ;;
        "pip"|"pypi"|"python")
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                pip show "$package" 2>/dev/null | grep "^Location:" | awk '{print $2}' || echo "")
            ;;
        *)
            # Try to find using locate or find
            locations=$(docker run --rm --platform "$PLATFORM" "$image" \
                find /usr /opt /home -name "*${package}*" -type f 2>/dev/null | head -10 | tr '\n' ',' | sed 's/,$//' || echo "unknown")
            ;;
    esac
    
    echo "${locations:-unknown}"
}

# Determine package type from PURL
get_package_type_from_purl() {
    local purl="$1"
    
    if [[ "$purl" == pkg:deb/* ]]; then
        echo "deb"
    elif [[ "$purl" == pkg:rpm/* ]]; then
        echo "rpm"
    elif [[ "$purl" == pkg:apk/* ]]; then
        echo "apk"
    elif [[ "$purl" == pkg:npm/* ]]; then
        echo "npm"
    elif [[ "$purl" == pkg:pypi/* ]]; then
        echo "pip"
    elif [[ "$purl" == pkg:gem/* ]]; then
        echo "gem"
    elif [[ "$purl" == pkg:golang/* ]]; then
        echo "go"
    else
        echo "unknown"
    fi
}

# Compare versions (returns 0 if v1 >= v2)
version_gte() {
    local v1="$1"
    local v2="$2"
    
    # Handle empty versions
    [ -z "$v1" ] && return 1
    [ -z "$v2" ] && return 0
    
    [ "$(printf '%s\n' "$v2" "$v1" | sort -V | head -n1)" = "$v2" ]
}

# Check if CVE is in allowlist
is_in_allowlist() {
    local cve="$1"
    local package="$2"
    
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        return 1
    fi
    
    # Check if CVE+package combination is allowlisted
    local match=$(jq -r --arg cve "$cve" --arg pkg "$package" '
        .entries[]? | select(.cve == $cve and .package == $pkg) | .cve
    ' "$ALLOWLIST_FILE" 2>/dev/null)
    
    [ -n "$match" ]
}

# Get CVEs for an image with detailed info
get_cves_with_details() {
    local image="$1"
    local output_file="$2"
    
    echo -e "${BLUE}Scanning for CVEs...${NC}"
    
    # Get CVEs in SARIF format (supported format with detailed info)
    if ! docker scout cves "$image" \
        --platform "$PLATFORM" \
        --only-severity "$SEVERITY_FILTER" \
        --format sarif \
        --output "$output_file" 2>&1; then
        echo -e "${YELLOW}Warning: CVE scan had issues${NC}"
    fi
    
    # Check if output file exists and has content
    if [ ! -f "$output_file" ] || [ ! -s "$output_file" ]; then
        echo '{"runs":[{"results":[],"tool":{"driver":{"rules":[]}}}]}' > "$output_file"
    fi
    
    echo -e "${GREEN}✓ CVE scan complete${NC}"
}

# Parse SARIF format to extract vulnerabilities
parse_sarif_vulnerabilities() {
    local sarif_file="$1"
    
    jq '
    .runs[0] as $run |
    [($run.results // [])[] | . as $result |
        (($run.tool.driver.rules // [])[] | select(.id == $result.ruleId)) as $rule |
        {
            cve: $result.ruleId,
            severity: ($rule.properties.cvssV3_severity // $rule.properties.severity // "unknown"),
            cvss_score: ($rule.properties."security-severity" // "0"),
            package: (($rule.properties.purls[0] // "") | split("@")[0] | split("/")[-1]),
            version: (($rule.properties.purls[0] // "@unknown") | split("@")[1] | split("?")[0]),
            fixed_version: ($rule.properties.fixed_version // "none"),
            purl: ($rule.properties.purls[0] // ""),
            description: (($rule.help.text // "") | split("\n")[0])
        }
    ] | unique_by(.cve + .package)' "$sarif_file" 2>/dev/null || echo "[]"
}

# Main filtering function
filter_vulnerabilities() {
    local image="$1"
    local safe_name="$2"
    
    local sbom_file="${OUTPUT_DIR}/${safe_name}-sbom.json"
    local cves_file="${OUTPUT_DIR}/${safe_name}-cves-raw.json"
    local filtered_file="${OUTPUT_DIR}/${safe_name}-filtered.json"
    
    echo ""
    echo "======================================"
    echo -e "Processing: ${BLUE}$image${NC}"
    echo "======================================"
    
    # Pull image
    echo "Pulling image..."
    if ! docker pull --platform "$PLATFORM" "$image" > /dev/null 2>&1; then
        echo -e "${RED}Failed to pull image: $image${NC}"
        return 1
    fi
    
    # Generate SBOM
    generate_sbom "$image" "$sbom_file"
    
    # Get CVEs
    get_cves_with_details "$image" "$cves_file"
    
    # Extract packages from SBOM
    local sbom_packages=$(extract_packages_with_locations "$sbom_file")
    
    # Parse CVEs and filter
    echo -e "${BLUE}Filtering vulnerabilities...${NC}"
    
    local verified_cves="[]"
    local false_positives="[]"
    local allowlisted="[]"
    local location_info="[]"
    
    # Parse vulnerabilities from SARIF format
    local parsed_vulns=$(parse_sarif_vulnerabilities "$cves_file")
    local vuln_count=$(echo "$parsed_vulns" | jq 'length' 2>/dev/null || echo "0")
    
    if [ "$vuln_count" -gt 0 ]; then
        # Process each vulnerability
        while IFS= read -r vuln; do
            local cve=$(echo "$vuln" | jq -r '.cve // .vulnerability // "unknown"')
            local package=$(echo "$vuln" | jq -r '.package // .artifact.name // "unknown"')
            local detected_version=$(echo "$vuln" | jq -r '.version // .artifact.version // "unknown"')
            local fixed_version=$(echo "$vuln" | jq -r '.fixed_version // .fix.versions[0] // "none"')
            local severity=$(echo "$vuln" | jq -r '.severity // "unknown"')
            local purl=$(echo "$vuln" | jq -r '.purl // .artifact.purl // ""')
            
            # Determine package type
            local pkg_type=$(get_package_type_from_purl "$purl")
            
            # Check allowlist first
            if is_in_allowlist "$cve" "$package"; then
                local allowlist_entry=$(jq -n \
                    --arg cve "$cve" \
                    --arg package "$package" \
                    --arg version "$detected_version" \
                    --arg reason "In allowlist" \
                    '{cve: $cve, package: $package, version: $version, reason: $reason}')
                allowlisted=$(echo "$allowlisted" | jq --argjson entry "$allowlist_entry" '. + [$entry]')
                continue
            fi
            
            # Get actual installed version
            local actual_version=$(get_actual_installed_version "$image" "$package" "$pkg_type")
            
            # Get package location
            local pkg_location=$(find_package_location "$image" "$package" "$pkg_type")
            
            # Build location info
            local loc_entry=$(jq -n \
                --arg package "$package" \
                --arg pkg_type "$pkg_type" \
                --arg location "$pkg_location" \
                --arg purl "$purl" \
                '{package: $package, type: $pkg_type, location: $location, purl: $purl}')
            location_info=$(echo "$location_info" | jq --argjson entry "$loc_entry" '. + [$entry]')
            
            # Build CVE entry with all details
            local cve_entry=$(jq -n \
                --arg cve "$cve" \
                --arg package "$package" \
                --arg detected_version "$detected_version" \
                --arg actual_version "${actual_version:-unknown}" \
                --arg fixed_version "$fixed_version" \
                --arg severity "$severity" \
                --arg pkg_type "$pkg_type" \
                --arg location "$pkg_location" \
                --arg purl "$purl" \
                '{
                    cve: $cve,
                    package: $package,
                    detected_version: $detected_version,
                    actual_version: $actual_version,
                    fixed_version: $fixed_version,
                    severity: $severity,
                    package_type: $pkg_type,
                    location: $location,
                    purl: $purl
                }')
            
            # Check for false positive
            local is_false_positive=false
            local fp_reason=""
            
            if [ -n "$actual_version" ] && [ "$actual_version" != "unknown" ]; then
                if [ "$actual_version" != "$detected_version" ]; then
                    if [ "$fixed_version" != "none" ] && version_gte "$actual_version" "$fixed_version"; then
                        is_false_positive=true
                        fp_reason="Actual version ($actual_version) >= fixed version ($fixed_version)"
                    fi
                fi
            fi
            
            if [ "$is_false_positive" = true ]; then
                cve_entry=$(echo "$cve_entry" | jq --arg reason "$fp_reason" '. + {false_positive: true, reason: $reason}')
                false_positives=$(echo "$false_positives" | jq --argjson entry "$cve_entry" '. + [$entry]')
            else
                cve_entry=$(echo "$cve_entry" | jq '. + {false_positive: false}')
                verified_cves=$(echo "$verified_cves" | jq --argjson entry "$cve_entry" '. + [$entry]')
            fi
            
        done < <(echo "$parsed_vulns" | jq -c '.[]?' 2>/dev/null)
    fi
    
    # Count results
    local verified_count=$(echo "$verified_cves" | jq 'length')
    local fp_count=$(echo "$false_positives" | jq 'length')
    local allowlist_count=$(echo "$allowlisted" | jq 'length')
    
    # Generate filtered report
    jq -n \
        --arg image "$image" \
        --arg platform "$PLATFORM" \
        --arg scan_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg severity_filter "$SEVERITY_FILTER" \
        --argjson verified_count "$verified_count" \
        --argjson fp_count "$fp_count" \
        --argjson allowlist_count "$allowlist_count" \
        --argjson original_count "$vuln_count" \
        --argjson verified "$verified_cves" \
        --argjson false_positives "$false_positives" \
        --argjson allowlisted "$allowlisted" \
        --argjson locations "$location_info" \
        '{
            metadata: {
                image: $image,
                platform: $platform,
                scan_date: $scan_date,
                severity_filter: $severity_filter,
                sbom_based_filtering: true
            },
            summary: {
                original_cve_count: $original_count,
                verified_cve_count: $verified_count,
                false_positive_count: $fp_count,
                allowlisted_count: $allowlist_count,
                reduction_percentage: (if $original_count > 0 then ((($fp_count + $allowlist_count) / $original_count) * 100 | floor) else 0 end)
            },
            verified_vulnerabilities: $verified,
            false_positives: $false_positives,
            allowlisted: $allowlisted,
            package_locations: $locations
        }' > "$filtered_file"
    
    # Print summary
    echo ""
    echo -e "${GREEN}======================================"
    echo "Filtering Results"
    echo "======================================${NC}"
    echo -e "Original CVEs:     ${YELLOW}$vuln_count${NC}"
    echo -e "Verified CVEs:     ${RED}$verified_count${NC}"
    echo -e "False Positives:   ${GREEN}$fp_count${NC}"
    echo -e "Allowlisted:       ${BLUE}$allowlist_count${NC}"
    echo ""
    echo -e "Report saved: ${BLUE}$filtered_file${NC}"
    
    return 0
}

# Add entry to allowlist
add_to_allowlist() {
    local cve="$1"
    local package="$2"
    local reason="$3"
    local expires="${4:-$(date -d '+1 year' +%Y-%m-%d)}"
    
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        create_default_allowlist
    fi
    
    # Add new entry
    local new_entry=$(jq -n \
        --arg cve "$cve" \
        --arg package "$package" \
        --arg reason "$reason" \
        --arg expires "$expires" \
        --arg added "$(date +%Y-%m-%d)" \
        '{cve: $cve, package: $package, reason: $reason, expires: $expires, added_by: "sbom-filter.sh", added_date: $added}')
    
    jq --argjson entry "$new_entry" '.entries += [$entry]' "$ALLOWLIST_FILE" > "${ALLOWLIST_FILE}.tmp" && \
        mv "${ALLOWLIST_FILE}.tmp" "$ALLOWLIST_FILE"
    
    echo -e "${GREEN}✓ Added to allowlist: $cve ($package)${NC}"
}

# Show usage
usage() {
    cat << EOF
SBOM-Based Vulnerability Filter

Usage: $0 [OPTIONS] <command>

Commands:
  scan <image>              Scan a single image (e.g., base:debian)
  scan-all                  Scan all predefined images
  add-allowlist             Add CVE to allowlist
  show-allowlist            Display current allowlist
  
Options:
  -r, --registry REGISTRY   Container registry (default: $REGISTRY)
  -p, --platform PLATFORM   Target platform (default: $PLATFORM)
  -s, --severity SEVERITY   Severity filter (default: $SEVERITY_FILTER)
  -o, --output DIR          Output directory (default: $OUTPUT_DIR)
  -h, --help                Show this help message

Examples:
  $0 scan python:latest
  $0 scan mcr.microsoft.com/devcontainers/base:debian
  $0 add-allowlist CVE-2024-1234 openssl "Fixed in base image"
  $0 --severity critical scan-all

EOF
}

# Main entry point
main() {
    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -p|--platform)
                PLATFORM="$2"
                shift 2
                ;;
            -s|--severity)
                SEVERITY_FILTER="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                mkdir -p "$OUTPUT_DIR"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            scan)
                shift
                check_prerequisites
                create_default_allowlist
                
                if [ -z "$1" ]; then
                    echo -e "${RED}Error: Image name required${NC}"
                    usage
                    exit 1
                fi
                
                local image="$1"
                # Add registry prefix if not a full path
                if [[ "$image" != *"/"* ]]; then
                    image="${REGISTRY}/${image}"
                fi
                
                local safe_name=$(echo "$image" | sed 's/[^a-zA-Z0-9]/-/g')
                filter_vulnerabilities "$image" "$safe_name"
                exit $?
                ;;
            scan-all)
                shift
                check_prerequisites
                create_default_allowlist
                
                # Predefined images to scan
                local IMAGES=(
                    "base:debian"
                    "base:ubuntu"
                    "base:alpine"
                    "python:latest"
                    "javascript-node:latest"
                    "typescript-node:latest"
                    "cpp:latest"
                    "go:latest"
                    "java:latest"
                    "rust:latest"
                    "ruby:latest"
                    "php:latest"
                )
                
                for img in "${IMAGES[@]}"; do
                    local full_image="${REGISTRY}/${img}"
                    local safe_name=$(echo "$full_image" | sed 's/[^a-zA-Z0-9]/-/g')
                    filter_vulnerabilities "$full_image" "$safe_name" || true
                done
                
                echo ""
                echo -e "${GREEN}======================================"
                echo "All scans complete!"
                echo "Reports saved in: $OUTPUT_DIR"
                echo "======================================${NC}"
                exit 0
                ;;
            add-allowlist)
                shift
                if [ $# -lt 3 ]; then
                    echo -e "${RED}Error: Required: CVE PACKAGE REASON${NC}"
                    echo "Usage: $0 add-allowlist CVE-2024-1234 openssl \"Reason for allowlisting\""
                    exit 1
                fi
                add_to_allowlist "$1" "$2" "$3" "${4:-}"
                exit 0
                ;;
            show-allowlist)
                if [ -f "$ALLOWLIST_FILE" ]; then
                    jq '.' "$ALLOWLIST_FILE"
                else
                    echo "No allowlist file found at: $ALLOWLIST_FILE"
                fi
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown command: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
    
    # No command specified
    usage
    exit 1
}

main "$@"
