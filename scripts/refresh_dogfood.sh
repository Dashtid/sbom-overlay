#!/usr/bin/env bash
# Regenerate the Syft side of the dicom-fuzzer dogfood fixture.
#
# Run from the repo root. Requires syft on PATH and a populated
# c:/code-two/dicom-fuzzer/.venv. Manual side is hand-curated and not
# touched by this script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DICOM_FUZZER_VENV="${DICOM_FUZZER_VENV:-c:/code-two/dicom-fuzzer/.venv}"
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/dogfood/dicom-fuzzer-1.11.0"
OUT="$FIXTURE_DIR/syft.spdx.json"

if ! command -v syft >/dev/null 2>&1; then
  echo "[!] syft not found on PATH. Install from https://github.com/anchore/syft" >&2
  exit 1
fi

if [ ! -d "$DICOM_FUZZER_VENV" ]; then
  echo "[!] venv not found at $DICOM_FUZZER_VENV" >&2
  echo "    Set DICOM_FUZZER_VENV or populate the venv before refreshing." >&2
  exit 1
fi

echo "[i] scanning $DICOM_FUZZER_VENV"
syft scan "dir:$DICOM_FUZZER_VENV" \
  -o "spdx-json=$OUT" \
  --source-name dicom-fuzzer \
  --source-version 1.11.0 \
  --override-default-catalogers python-installed-package-cataloger

echo "[+] wrote $OUT"
