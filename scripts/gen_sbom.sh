# FILE: scripts/gen_sbom.sh
set -euo pipefail
python -m pip install -U cyclonedx-bom >/dev/null 2>&1 || true
cyclonedx-bom -o sbom.json -e
echo "SBOM -> sbom.json"