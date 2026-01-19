#!/bin/bash

# Script to scan published devcontainer images for vulnerabilities using Docker Scout
# Pulls images from registry and scans them

set -e


OUTPUT_FILE="/workspaces/images/scan/pull-scan-results.json"
OUTPUT_SUMMARY="/workspaces/images/scan/pull-scan-summary.txt"
TEMP_SCAN_FILE="/tmp/scout-scan-output.txt"
REGISTRY="mcr.microsoft.com/devcontainers"

# Ensure output directory exists
OUTPUT_DIR="$(dirname \"$OUTPUT_FILE\")"
mkdir -p "$OUTPUT_DIR"

# Define images to scan
# Format: "image_name:variant1,variant2|arch1,arch2"
IMAGES=(
   # "anaconda:3|linux/amd64,linux/arm64"
   # "miniconda:3|linux/amd64,linux/arm64"
    "base:alpine3.21,alpine3.20,alpine|linux/amd64,linux/arm64"
    "base:debian12,debian,debian13|linux/amd64,linux/arm64"
    "base:ubuntu,ubuntu24.04,ubuntu22.04|linux/amd64,linux/arm64"
   # "python:3.14-trixie,3.13-trixie,3.12-trixie,3.11-trixie,3.10-trixie,3.14-bookworm,3.13-bookworm,3.12-bookworm,3.11-bookworm,3.10-bookworm|linux/amd64,linux/arm64"
   # "javascript-node:24-trixie,22-trixie,20-trixie,24-bookworm,22-bookworm,20-bookworm,24-bullseye,22-bullseye,20-bullseye|linux/amd64,linux/arm64"
   # "typescript-node:24-trixie,22-trixie,20-trixie,24-bookworm,22-bookworm,20-bookworm,24-bullseye,22-bullseye,20-bullseye|linux/amd64,linux/arm64"
   # "go:1.25-trixie,1.24-trixie,1.25-bookworm,1.24-bookworm,1.24-bullseye|linux/amd64,linux/arm64"
   # "java:25-trixie,21-trixie,17-trixie,11-trixie,25-bookworm,21-bookworm,17-bookworm,11-bookworm|linux/amd64,linux/arm64"
   # "java-8:trixie,bookworm|linux/amd64,linux/arm64"
   # "dotnet:10.0-noble,9.0-bookworm-slim,9.0-noble,8.0-bookworm-slim,8.0-noble,8.0-jammy|linux/amd64,linux/arm64"
   # "cpp:trixie,bookworm,noble,jammy|linux/amd64,linux/arm64"
   # "rust:trixie,bookworm,bullseye|linux/amd64,linux/arm64"
   # "php:8.5-apache-trixie,8.4-apache-trixie,8.3-apache-trixie,8.2-apache-trixie,8.5-apache-bookworm,8.4-apache-bookworm,8.3-apache-bookworm,8.2-apache-bookworm|linux/amd64,linux/arm64"
   # "ruby:3.4-trixie,3.3-trixie,3.2-trixie,3.4-bookworm,3.3-bookworm,3.2-bookworm,3.4-bullseye,3.3-bullseye,3.2-bullseye|linux/amd64,linux/arm64"
   # "jekyll:3.4-bookworm,3.3-bookworm,3.3-bullseye|linux/amd64,linux/arm64"
   # "universal:noble|linux/amd64,linux/arm64"
)

echo "======================================"
echo "DevContainer Published Images Vulnerability Scan"
echo "======================================"
echo "Registry: $REGISTRY"
echo "Output: $OUTPUT_FILE"
echo "Summary: $OUTPUT_SUMMARY"
echo "======================================"
echo ""

# Check if jq is installed for JSON parsing
if ! command -v jq &> /dev/null; then
    echo "Installing jq for JSON processing..."
    apt-get update && apt-get install -y jq > /dev/null 2>&1
fi

# Check if docker scout is available, install if not
if ! docker scout version &>/dev/null; then
    echo "Installing Docker Scout..."
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
    
    if ! docker scout version &>/dev/null; then
        echo "Error: Failed to install Docker Scout."
        exit 1
    fi
    echo "✓ Docker Scout installed"
    echo ""
fi

# Initialize JSON output
echo "{" > "$OUTPUT_FILE"
echo '  "scan_date": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",' >> "$OUTPUT_FILE"
echo '  "registry": "'$REGISTRY'",' >> "$OUTPUT_FILE"
echo '  "images": [' >> "$OUTPUT_FILE"

# Initialize summary
{
    echo "======================================"
    echo "Vulnerability Scan Summary"
    echo "Generated: $(date)"
    echo "Registry: $REGISTRY"
    echo "======================================"
    echo ""
} > "$OUTPUT_SUMMARY"

# Calculate total scans
IMAGE_COUNT=${#IMAGES[@]}
TOTAL_SCANS=0
COMPLETED_SCANS=0
FIRST_IMAGE=true

for image_spec in "${IMAGES[@]}"; do
    IFS=':' read -r img_name rest <<< "$image_spec"
    IFS='|' read -r variants archs <<< "$rest"
    VARIANT_COUNT=$(echo "$variants" | tr ',' '\n' | wc -l)
    ARCH_COUNT=$(echo "$archs" | tr ',' '\n' | wc -l)
    TOTAL_SCANS=$((TOTAL_SCANS + VARIANT_COUNT * ARCH_COUNT))
done

echo "Total images to scan: $IMAGE_COUNT"
echo "Total pulls: $TOTAL_SCANS"
echo ""

# Iterate through each image
for image_spec in "${IMAGES[@]}"; do
    # Parse image specification: "image_name:variant1,variant2|arch1,arch2"
    IFS=':' read -r IMAGE_NAME rest <<< "$image_spec"
    IFS='|' read -r variants archs <<< "$rest"
    VARIANTS=$(echo "$variants" | tr ',' '\n')
    ARCHITECTURES=$(echo "$archs" | tr ',' '\n')
    
    # Add comma before image if not first
    if [ "$FIRST_IMAGE" = false ]; then
        echo "    ," >> "$OUTPUT_FILE"
    fi
    FIRST_IMAGE=false
    
    echo "    {" >> "$OUTPUT_FILE"
    echo "      \"name\": \"$IMAGE_NAME\"," >> "$OUTPUT_FILE"
    echo "      \"variants\": [" >> "$OUTPUT_FILE"
    
    FIRST_VARIANT=true
    
    # Iterate through variants
    while IFS= read -r variant; do
        # Add comma before variant if not first
        if [ "$FIRST_VARIANT" = false ]; then
            echo "        ," >> "$OUTPUT_FILE"
        fi
        FIRST_VARIANT=false
        
        echo "        {" >> "$OUTPUT_FILE"
        echo "          \"variant\": \"$variant\"," >> "$OUTPUT_FILE"
        echo "          \"scans\": [" >> "$OUTPUT_FILE"
        
        FIRST_ARCH=true
        
        # Iterate through architectures
        while IFS= read -r arch; do
            COMPLETED_SCANS=$((COMPLETED_SCANS + 1))
            
            echo "--------------------------------------"
            echo "[$COMPLETED_SCANS/$TOTAL_SCANS] Scanning: $IMAGE_NAME"
            echo "Variant: $variant | Arch: $arch"
            echo "--------------------------------------"
            
            # Add comma before arch if not first
            if [ "$FIRST_ARCH" = false ]; then
                echo "            ," >> "$OUTPUT_FILE"
            fi
            FIRST_ARCH=false
            
            ARCH_TAG=$(echo "$arch" | tr '/' '-')
            # Construct the image tag based on common devcontainer naming patterns
            IMAGE_TAG="${REGISTRY}/${IMAGE_NAME}:${variant}"
            
            echo "Pulling image: $IMAGE_TAG"
            PULL_SUCCESS=true
            docker pull --platform "$arch" "$IMAGE_TAG" > /dev/null 2>&1 || PULL_SUCCESS=false
            
            if [ "$PULL_SUCCESS" = false ]; then
                echo "⚠️  Pull failed, skipping scan"
                echo "            {" >> "$OUTPUT_FILE"
                echo "              \"architecture\": \"$arch\"," >> "$OUTPUT_FILE"
                echo "              \"tag\": \"$IMAGE_TAG\"," >> "$OUTPUT_FILE"
                echo "              \"pull_status\": \"failed\"," >> "$OUTPUT_FILE"
                echo "              \"vulnerabilities\": []" >> "$OUTPUT_FILE"
                echo "            }" >> "$OUTPUT_FILE"
                echo ""
                continue
            fi
            
            echo "✓ Pull completed"
            
            # Run vulnerability scan with SARIF format for better parsing (includes fixed versions)
            echo "Scanning..."
            docker scout cves "$IMAGE_TAG" --platform "$arch" --only-severity critical,high --only-fixed --format sarif 2>/dev/null > "$TEMP_SCAN_FILE" || true
            
            # Parse vulnerabilities from SARIF output
            if jq -e '.runs[0].results' "$TEMP_SCAN_FILE" >/dev/null 2>&1; then
                # Valid SARIF JSON output - extract vulnerabilities with fixed versions
                VULNS=$(jq -c '[.runs[0].results[]? | .message.text | capture("Vulnerability\\s*:(?<cve>CVE-[^\\s]+).*Severity\\s*:(?<severity>[^\\s]+).*Package\\s*:pkg:[^/]+/[^/]+/(?<package>[^@]+)@(?<version>[^?]+).*Fixed version\\s*:(?<fixed_version>[^\\s]+)"; "m")]' "$TEMP_SCAN_FILE" 2>/dev/null || echo "[]")
                VULN_COUNT=$(echo "$VULNS" | jq 'length')
            else
                # JSON parsing failed, fall back to empty array
                echo "⚠️  Failed to parse scan output"
                VULNS="[]"
                VULN_COUNT=0
            fi
            
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo "⚠️  Found $VULN_COUNT fixable vulnerabilit(y|ies)"
            else
                echo "✓ No critical/high fixable vulnerabilities"
            fi
            
            # Write to JSON output
            echo "            {" >> "$OUTPUT_FILE"
            echo "              \"architecture\": \"$arch\"," >> "$OUTPUT_FILE"
            echo "              \"tag\": \"$IMAGE_TAG\"," >> "$OUTPUT_FILE"
            echo "              \"pull_status\": \"success\"," >> "$OUTPUT_FILE"
            echo "              \"vulnerabilities\": $VULNS" >> "$OUTPUT_FILE"
            echo "            }" >> "$OUTPUT_FILE"
            
            # Add to summary
            {
                echo "[$IMAGE_NAME:$variant-$ARCH_TAG]"
                if [ "$VULN_COUNT" -gt 0 ]; then
                    echo "  Status: ⚠️  $VULN_COUNT vulnerabilities found"
                    echo "$VULNS" | jq -r '.[] | "  - \(.cve) (\(.severity)): \(.package) \(.version) -> \(.fixed_version)"'
                else
                    echo "  Status: ✓ No critical/high vulnerabilities with fixes"
                fi
                echo ""
            } >> "$OUTPUT_SUMMARY"
            
            # Remove the pulled image to save disk space
            echo "Cleaning up image: $IMAGE_TAG"
            if docker rmi -f "$IMAGE_TAG" > /dev/null 2>&1; then
                echo "✓ Image removed successfully"
            else
                echo "⚠️  Failed to remove image (may already be deleted)"
            fi
            
            echo ""
        done <<< "$ARCHITECTURES"
        
        echo "          ]" >> "$OUTPUT_FILE"
        echo "        }" >> "$OUTPUT_FILE"
    done <<< "$VARIANTS"
    
    echo "      ]" >> "$OUTPUT_FILE"
    echo "    }" >> "$OUTPUT_FILE"
done

# Finalize JSON output
echo "  ]" >> "$OUTPUT_FILE"
echo "}" >> "$OUTPUT_FILE"

# Clean up temp file
rm -f "$TEMP_SCAN_FILE"

echo "======================================"
echo "All scans completed!"
echo "======================================"
echo ""
echo "Results saved to:"
echo "  JSON: $OUTPUT_FILE"
echo "  Summary: $OUTPUT_SUMMARY"
echo ""

# Display summary statistics
TOTAL_VULNS=$(jq '[.images[].variants[].scans[].vulnerabilities | length] | add' "$OUTPUT_FILE")
IMAGES_WITH_VULNS=$(jq '[.images[].variants[].scans[] | select((.vulnerabilities | length) > 0)] | length' "$OUTPUT_FILE")

echo "Summary Statistics:"
echo "  Total scans: $COMPLETED_SCANS"
echo "  Total vulnerabilities: $TOTAL_VULNS"
echo "  Images with vulnerabilities: $IMAGES_WITH_VULNS"
echo ""

# Final cleanup - remove any remaining pulled images
echo "======================================"
echo "Final cleanup of pulled images..."
echo "======================================"
PULLED_IMAGES=$(docker images --filter "reference=$REGISTRY/*" --format "{{.Repository}}:{{.Tag}}")
if [ -n "$PULLED_IMAGES" ]; then
    echo "$PULLED_IMAGES" | xargs -r docker rmi -f > /dev/null 2>&1 || true
    echo "✓ Removed remaining pulled images"
else
    echo "✓ No pulled images to clean up"
fi
echo ""
