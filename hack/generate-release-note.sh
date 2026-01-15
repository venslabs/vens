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

## Quick start
\`\`\`bash
export OPENAI_API_KEY="your-key"
vens generate \\
  --config-file config.yaml \\
  --sboms sbom.cdx.json \\
  trivy.json \\
  output_vex.json
\`\`\`
EOX
