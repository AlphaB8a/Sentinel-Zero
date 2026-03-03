#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

APPLY_DIR=""
OUT_DIR="${ROOT}/docs/integrations/kf_mirror_exports"
MIRROR_ID="$(date -u +"%Y%m%dT%H%M%SZ")"

usage() {
  cat <<'EOF'
Usage:
  scripts/integration/kf_mirror_export.sh --apply-dir <path> [--out-dir <path>] [--mirror-id <id>]

Description:
  Export a one-way standalone mirror bundle for KF attachment.
  The bundle is file-based (no API coupling) and includes a sha256 manifest.
EOF
}

while (($# > 0)); do
  case "$1" in
    --apply-dir)
      shift
      if (($# == 0)); then
        echo "[kf-mirror][FAIL] --apply-dir requires a value"
        exit 2
      fi
      APPLY_DIR="$1"
      ;;
    --out-dir)
      shift
      if (($# == 0)); then
        echo "[kf-mirror][FAIL] --out-dir requires a value"
        exit 2
      fi
      OUT_DIR="$1"
      ;;
    --mirror-id)
      shift
      if (($# == 0)); then
        echo "[kf-mirror][FAIL] --mirror-id requires a value"
        exit 2
      fi
      MIRROR_ID="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[kf-mirror][FAIL] unknown arg: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ -z "${APPLY_DIR}" ]]; then
  echo "[kf-mirror][FAIL] --apply-dir is required"
  exit 2
fi

if [[ ! -d "${APPLY_DIR}" ]]; then
  echo "[kf-mirror][FAIL] apply dir does not exist: ${APPLY_DIR}"
  exit 1
fi

REQUIRED_FILES=(
  "plan.resolved.yaml"
  "resolved.sha256"
  "preflight.json"
  "apply.sh"
  "rollback.sh"
  "promotion.receipt.json"
  "trust-root.json"
  "after/verify.json"
  "after/promotion_audit_chain.ndjson"
)

for rel in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "${APPLY_DIR}/${rel}" ]]; then
    echo "[kf-mirror][FAIL] missing required file: ${APPLY_DIR}/${rel}"
    exit 1
  fi
done

DEST_DIR="${OUT_DIR}/${MIRROR_ID}"
mkdir -p "${DEST_DIR}/after"

for rel in "${REQUIRED_FILES[@]}"; do
  mkdir -p "$(dirname "${DEST_DIR}/${rel}")"
  cp -f "${APPLY_DIR}/${rel}" "${DEST_DIR}/${rel}"
done

MANIFEST_PATH="${DEST_DIR}/mirror_manifest.json"
CHECKS_TMP="$(mktemp)"
trap 'rm -f "${CHECKS_TMP}"' EXIT

for rel in "${REQUIRED_FILES[@]}"; do
  sha="$(sha256sum "${DEST_DIR}/${rel}" | awk '{print $1}')"
  size="$(wc -c < "${DEST_DIR}/${rel}")"
  printf '%s|%s|%s\n' "${rel}" "${sha}" "${size}" >>"${CHECKS_TMP}"
done

python3 - <<'PY' "${MANIFEST_PATH}" "${DEST_DIR}" "${APPLY_DIR}" "${CHECKS_TMP}" "${MIRROR_ID}"
import json
import pathlib
import sys
from datetime import datetime, timezone

manifest_path = pathlib.Path(sys.argv[1])
dest_dir = pathlib.Path(sys.argv[2])
apply_dir = pathlib.Path(sys.argv[3])
checks_path = pathlib.Path(sys.argv[4])
mirror_id = sys.argv[5]

files = []
for line in checks_path.read_text(encoding="utf-8").splitlines():
    rel, sha256, size = line.split("|")
    files.append(
        {
            "path": rel,
            "sha256": sha256,
            "size_bytes": int(size),
        }
    )

doc = {
    "attachment_mode": "standalone_mirror_v1",
    "target_host": "KF",
    "mirror_id": mirror_id,
    "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source_apply_dir": str(apply_dir),
    "mirror_dir": str(dest_dir),
    "files": sorted(files, key=lambda item: item["path"]),
}

manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "KF_MIRROR_EXPORT_OK dir=${DEST_DIR} manifest=${MANIFEST_PATH}"
