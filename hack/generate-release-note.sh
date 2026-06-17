# Forked from https://github.com/containerd/nerdctl/blob/v2.2.1/hack/generate-release-note.sh
# Apache License 2.0

#!/bin/bash
cat <<-EOX
## Changes
(To be documented)

## About the binaries
The binaries were built automatically on GitHub Actions.

### Installation
Extract the archive and move the binary to your PATH.
\`\`\`bash
tar -xzf vens-<VERSION>-<OS>-<ARCH>.tar.gz
sudo mv vens /usr/local/bin/
\`\`\`

### Verifying this release
Release artifacts are signed with cosign keyless — Sigstore cert bound to the GitHub Actions release workflow identity.
\`\`\`bash
# Verify the signature over the checksums file
cosign verify-blob \\
  --bundle SHA256SUMS.sigstore.json \\
  --certificate-identity-regexp '^https://github.com/venslabs/vens/\.github/workflows/release\.yml@refs/tags/v' \\
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\
  SHA256SUMS

# Then check your downloaded archive against the trusted checksums
sha256sum --check --ignore-missing SHA256SUMS
\`\`\`
A GitHub build-provenance attestation is also published; see the docs for verification.

## Quick start
\`\`\`bash
export OPENAI_API_KEY="your-key"
vens generate \\
  --config-file config.yaml \\
  --sbom-serial-number "urn:uuid:..." \\
  report.json \\
  output.vex.json
\`\`\`
EOX
