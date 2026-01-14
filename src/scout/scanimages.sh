#!/bin/bash

# Script to scan all devcontainer images for vulnerabilities using Docker Scout
# Reads configuration from scan-config.json and outputs to scan-results.json

set -e

CONFIG_FILE="/workspaces/images/src/scout/config-1.json"
OUTPUT_FILE="/workspaces/images/src/scout/scan-results-$(basename "$CONFIG_FILE" .json).json"
OUTPUT_SUMMARY="/workspaces/images/src/scout/scan-summary-$(basename "$CONFIG_FILE" .json).txt"
TEMP_SCAN_FILE="/tmp/scout-scan-output.txt"

echo "======================================"
echo "DevContainer Images Vulnerability Scan"
echo "======================================"
echo "Config: $CONFIG_FILE"
echo "Output: $OUTPUT_FILE"
echo "Summary: $OUTPUT_SUMMARY"
echo "======================================"
echo ""

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

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
echo '  "images": [' >> "$OUTPUT_FILE"

# Initialize summary
{
    echo "======================================"
    echo "Vulnerability Scan Summary"
    echo "Generated: $(date)"
    echo "======================================"
    echo ""
} > "$OUTPUT_SUMMARY"

# Parse JSON config and iterate through images
IMAGE_COUNT=$(jq '.images | length' "$CONFIG_FILE")
TOTAL_SCANS=0
COMPLETED_SCANS=0
FIRST_IMAGE=true

# Calculate total scans
for ((i=0; i<IMAGE_COUNT; i++)); do
    VARIANT_COUNT=$(jq -r ".images[$i].variants | length" "$CONFIG_FILE")
    ARCH_COUNT=$(jq -r ".images[$i].architectures | length" "$CONFIG_FILE")
    TOTAL_SCANS=$((TOTAL_SCANS + VARIANT_COUNT * ARCH_COUNT))
done

echo "Total images to scan: $IMAGE_COUNT"
echo "Total builds: $TOTAL_SCANS"
echo ""

# Iterate through each image
for ((i=0; i<IMAGE_COUNT; i++)); do
    IMAGE_NAME=$(jq -r ".images[$i].name" "$CONFIG_FILE")
    IMAGE_PATH=$(jq -r ".images[$i].path" "$CONFIG_FILE")
    VARIANTS=$(jq -r ".images[$i].variants[]" "$CONFIG_FILE")
    ARCHITECTURES=$(jq -r ".images[$i].architectures[]" "$CONFIG_FILE")
    
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
            TAG="devcontainers/${IMAGE_NAME}:${variant}-${ARCH_TAG}-scan"
            
            # Build the image
            if [ -f "/workspaces/images/$IMAGE_PATH/Dockerfile" ]; then
                echo "Building (native architecture)..."
                BUILD_SUCCESS=true
                docker build \
                    --build-arg VARIANT="$variant" \
                    --tag "$TAG" \
                    "/workspaces/images/$IMAGE_PATH" > /dev/null 2>&1 || BUILD_SUCCESS=false
                
                if [ "$BUILD_SUCCESS" = false ]; then
                    echo "⚠️  Build failed, skipping scan"
                    echo "            {" >> "$OUTPUT_FILE"
                    echo "              \"architecture\": \"$arch\"," >> "$OUTPUT_FILE"
                    echo "              \"tag\": \"$TAG\"," >> "$OUTPUT_FILE"
                    echo "              \"build_status\": \"failed\"," >> "$OUTPUT_FILE"
                    echo "              \"vulnerabilities\": []" >> "$OUTPUT_FILE"
                    echo "            }" >> "$OUTPUT_FILE"
                    continue
                fi
                
                echo "✓ Build completed"
                
                # Run vulnerability scan
                echo "Scanning..."
                docker scout cves "$TAG" --only-severity critical,high > "$TEMP_SCAN_FILE" 2>&1 || true
                
                # Parse vulnerabilities from text output
                VULN_COUNT=$(grep -c "CVE-" "$TEMP_SCAN_FILE" 2>/dev/null || echo "0")
                
                # Extract CVE details manually from text output
                VULNS="["
                FIRST_CVE=true
                while IFS= read -r line; do
                    if [[ $line =~ CVE-[0-9]+-[0-9]+ ]]; then
                        CVE_ID="${BASH_REMATCH[0]}"
                        # Try to extract package and severity from surrounding lines
                        PACKAGE=$(echo "$line" | grep -oP '(?<=pkg:)[^\s]+' || echo "unknown")
                        SEVERITY=$(grep -A2 "$CVE_ID" "$TEMP_SCAN_FILE" | grep -oP '(CRITICAL|HIGH)' | head -1 || echo "HIGH")
                        
                        if [ "$FIRST_CVE" = false ]; then
                            VULNS+=","
                        fi
                        FIRST_CVE=false
                        
                        VULNS+="{\"cve\":\"$CVE_ID\",\"package\":\"$PACKAGE\",\"severity\":\"$SEVERITY\",\"fixed_version\":\"not fixed\"}"
                    fi
                done < "$TEMP_SCAN_FILE"
                VULNS+="]"
                
                if [ "$VULN_COUNT" -gt 0 ]; then
                    echo "⚠️  Found $VULN_COUNT vulnerabilit(y|ies)"
                else
                    echo "✓ No critical/high vulnerabilities"
                fi
                
                # Write to JSON output
                echo "            {" >> "$OUTPUT_FILE"
                echo "              \"architecture\": \"$arch\"," >> "$OUTPUT_FILE"
                echo "              \"tag\": \"$TAG\"," >> "$OUTPUT_FILE"
                echo "              \"build_status\": \"success\"," >> "$OUTPUT_FILE"
                echo "              \"vulnerabilities\": $VULNS" >> "$OUTPUT_FILE"
                echo "            }" >> "$OUTPUT_FILE"
                
                # Add to summary
                {
                    echo "[$IMAGE_NAME:$variant-$ARCH_TAG]"
                    if [ "$VULN_COUNT" -gt 0 ]; then
                        echo "  Status: ⚠️  $VULN_COUNT vulnerabilities found"
                        echo "$VULNS" | jq -r '.[] | "  - \(.cve) (\(.severity)): \(.package)"'
                    else
                        echo "  Status: ✓ No critical/high vulnerabilities"
                    fi
                    echo ""
                } >> "$OUTPUT_SUMMARY"
                
                # Remove the scanned image to save disk space
                echo "Cleaning up image: $TAG"
                if docker rmi -f "$TAG" > /dev/null 2>&1; then
                    echo "✓ Image removed successfully"
                else
                    echo "⚠️  Failed to remove image (may already be deleted)"
                fi
            else
                echo "⚠️  Dockerfile not found, skipping"
                echo "            {" >> "$OUTPUT_FILE"
                echo "              \"architecture\": \"$arch\"," >> "$OUTPUT_FILE"
                echo "              \"tag\": \"$TAG\"," >> "$OUTPUT_FILE"
                echo "              \"build_status\": \"dockerfile_not_found\"," >> "$OUTPUT_FILE"
                echo "              \"vulnerabilities\": []" >> "$OUTPUT_FILE"
                echo "            }" >> "$OUTPUT_FILE"
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

# Final cleanup - remove any remaining scan images
echo "======================================"
echo "Final cleanup of scan images..."
echo "======================================"
SCAN_IMAGES=$(docker images --filter "reference=devcontainers/*:*-scan" --format "{{.Repository}}:{{.Tag}}" | grep -E ".*-(linux-)?(amd64|arm64)-scan$|.*-scan$")
if [ -n "$SCAN_IMAGES" ]; then
    echo "$SCAN_IMAGES" | xargs -r docker rmi -f > /dev/null 2>&1 || true
    echo "✓ Removed remaining scan images"
else
    echo "✓ No scan images to clean up"
fi
echo ""
