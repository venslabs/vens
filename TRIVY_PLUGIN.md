# Vens as a Trivy Plugin

Vens can be used as a Trivy plugin to evaluate and prioritize vulnerabilities based on context.

## Installation

Install vens as a Trivy plugin:

```bash
trivy plugin install github.com/fahedouch/vens
```

## Usage

Once installed, you can use vens commands directly through Trivy:

### 1. Generate VEX with LLM

Generate a VEX document from a Trivy scan report using LLM to prioritize vulnerabilities:

```bash
# Scan an image with Trivy
trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL > report.json

# Generate VEX using vens as a Trivy plugin
trivy vens generate --config-file config.yaml --sboms sbom1.cdx.json,sbom2.cdx.json report.json output.cdx
```

### 2. Enrich Reports with VEX

Enrich a Trivy vulnerability report with ratings and scores from a VEX document:

```bash
# Scan an image with Trivy
trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL > report.json

# Enrich the report with VEX statements
trivy vens enrich --vex vex.cdx.json report.json

# Or save to a file
trivy vens enrich --vex vex.cdx.json --output enriched-report.json report.json
```

## How it Works

### Plugin Detection

Vens automatically detects when it's running as a Trivy plugin by checking if the executable path contains `/.trivy/plugins/vens`. When running as a plugin, command examples are adjusted to show `trivy vens` instead of just `vens`.

### VEX Enrichment

The `enrich` command applies VEX ratings (OWASP scores) to a Trivy vulnerability report using simple Vulnerability ID matching:

1. **Score Extraction**: It extracts OWASP scores for each vulnerability from the VEX document.

2. **Direct Mapping**: For each vulnerability in the Trivy report, it matches the `VulnerabilityID` with the entries found in the VEX.

3. **Metadata Enrichment**: If a match is found, the OWASP score is applied to the `owasp_score` field within the `Custom` metadata of the vulnerability.

4. **Results**: Only vulnerabilities that have a corresponding entry with an OWASP score in the VEX document are enriched.

## VEX Matching Rules

Vens uses a direct mapping strategy:

- **Vulnerability ID**: Matches are made strictly on the vulnerability identifier (e.g., `CVE-2023-1234`).
- **Global Application**: The score from the VEX is applied to all instances of that vulnerability in the report, regardless of the package or component.

## Internal Implementation

Vens leverages Trivy's official types for seamless integration:
- **Trivy Types**: Uses `github.com/aquasecurity/trivy/pkg/types` for report structures.
- **CycloneDX**: Uses `github.com/CycloneDX/cyclonedx-go` for VEX parsing.

## Architecture

The plugin implementation includes:

1. **trivypluginutil**: Detects when running as a Trivy plugin
2. **vexenricher**: Enriches Trivy reports with VEX statements
3. **plugin.yaml**: Trivy plugin manifest defining supported platforms

## Standalone Usage

Vens can also be used as a standalone tool without Trivy:

```bash
# Direct usage
vens generate --config-file config.yaml --sboms sbom1.cdx.json report.json output.cdx
vens enrich --vex vex.cdx.json report.json
```

## References

- [Trivy Plugin Developer Guide](https://aquasecurity.github.io/trivy/latest/docs/plugin/developer-guide/)
- [CycloneDX VEX Specification](https://cyclonedx.org/capabilities/vex/)
- [OpenVEX](https://github.com/openvex)
