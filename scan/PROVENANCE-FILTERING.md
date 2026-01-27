# Using Provenance Attestations to Filter CVE False Positives

## Overview

Docker Scout sometimes reports CVEs from nested dependencies (base images) that the devcontainers team cannot directly action. This document describes how to use **provenance attestations** and Docker Scout's layer-aware filtering to separate actionable vulnerabilities from inherited ones.

## Key Discovery

The MCR devcontainer images **do have SLSA provenance attestations** attached! This provides:

1. **Source repository identification** - Confirms the image came from `https://github.com/devcontainers/images`
2. **Build materials** - Lists the base images used (e.g., `buildpack-deps@trixie-curl`)
3. **Build environment** - GitHub Actions workflow details, commit SHA, etc.

## Available Filtering Options

### Docker Scout Built-in Options

Docker Scout has native support for layer-aware CVE filtering:

```bash
# Exclude CVEs from base image (only show actionable ones)
docker scout cves IMAGE --ignore-base

# Show only CVEs from base image (for upstream awareness)
docker scout cves IMAGE --only-base

# Show package locations and layer information
docker scout cves IMAGE --locations
```

### Provenance Inspection

```bash
# Get full provenance attestation
docker buildx imagetools inspect IMAGE --format '{{json .Provenance}}'

# Extract base image materials
docker buildx imagetools inspect IMAGE --format '{{json .Provenance}}' | \
    jq '.["linux/amd64"].SLSA.materials'

# Get source repository
docker buildx imagetools inspect IMAGE --format '{{json .Provenance}}' | \
    jq '.["linux/amd64"].SLSA.invocation.environment.github_repository'
```

### SBOM Analysis

```bash
# Generate SBOM with source information
docker scout sbom --format json IMAGE

# Check image labels for devcontainer ownership
docker scout sbom --format json IMAGE | \
    jq '.source.image.config.config.Labels["dev.containers.source"]'
```

## Recommended Workflow

### 1. Quick Triage: Separate Actionable from Inherited CVEs

```bash
# Total CVEs (all layers)
docker scout cves IMAGE --only-severity critical,high --only-fixed --format sarif | \
    jq '.runs[0].results | length'

# Actionable CVEs (devcontainer layers only)
docker scout cves IMAGE --only-severity critical,high --only-fixed --ignore-base --format sarif | \
    jq '.runs[0].results | length'

# Inherited CVEs (base image only)
docker scout cves IMAGE --only-severity critical,high --only-fixed --only-base --format sarif | \
    jq '.runs[0].results | length'
```

### 2. Verify Image Provenance

Before trusting the `--ignore-base` results, verify the image has valid provenance:

```bash
# Check provenance exists and source is devcontainers
docker buildx imagetools inspect mcr.microsoft.com/devcontainers/base:debian --format '{{json .Provenance}}' | \
    jq '.["linux/amd64"].SLSA.invocation.environment.github_repository'
# Expected: "devcontainers/images"
```

### 3. Generate Comprehensive Reports

Use the new `provenance-scan.sh` script to generate:

- **Full scan results** - All CVEs for complete visibility
- **Actionable CVEs** - CVEs the devcontainers team can fix
- **Base image CVEs** - CVEs requiring upstream fixes
- **Supply chain analysis** - Build materials and provenance details

```bash
./scan/provenance-scan.sh
```

## Sample Output

For `mcr.microsoft.com/devcontainers/base:debian`:

| Metric | Count |
|--------|-------|
| Total fixable critical/high CVEs | 1 |
| Actionable (excluding base) | 0 |
| Inherited from base image | 1 |

The CVE (CVE-2025-68973 in gnupg2) comes from the `buildpack-deps@trixie-curl` base image and cannot be fixed by updating devcontainer layers.

## Integration with CI/CD

### Example GitHub Actions Workflow

```yaml
- name: Scan for actionable CVEs only
  run: |
    # Only fail if there are CVEs we can actually fix
    ACTIONABLE=$(docker scout cves $IMAGE --ignore-base --only-severity critical,high --only-fixed --format sarif | jq '.runs[0].results | length')
    if [ "$ACTIONABLE" -gt 0 ]; then
      echo "::error::Found $ACTIONABLE actionable vulnerabilities"
      exit 1
    fi
    echo "No actionable vulnerabilities found"

- name: Report base image CVEs (informational)
  run: |
    # Report but don't fail for base image CVEs
    docker scout cves $IMAGE --only-base --only-severity critical,high --only-fixed --format markdown > base-cves-report.md
```

## Limitations

1. **Provenance Mode**: MCR images use `buildkit_min_mode` provenance, which provides materials but not full build reproducibility
2. **Cross-Registry**: Provenance tracking may be incomplete for images built from multiple registries
3. **Feature Layers**: CVEs introduced by dev container features need additional analysis

## Files Added

- `scan/provenance-scan.sh` - Enhanced scan script with provenance and layer awareness
- `scan/provenance-reports/` - Output directory for detailed reports

## References

- [Docker SLSA Provenance Attestations](https://docs.docker.com/build/metadata/attestations/slsa-provenance/)
- [Docker Scout CVE Analysis](https://docs.docker.com/scout/explore/analysis/)
- [Creating Attestations](https://docs.docker.com/build/metadata/attestations/#creating-attestations)
