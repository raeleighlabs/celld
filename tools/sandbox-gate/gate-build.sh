#!/usr/bin/env bash
set -euo pipefail
helper="$(cd "$(dirname "$0")" && pwd)"
: "${GOCACHE:?set an explicit Go build cache directory}"
output="$1"
mkdir -p "$(dirname "$output")" "$GOCACHE"
export CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local GOMAXPROCS=1 GOWORK=off
unset GOFLAGS
go build -p=1 -buildmode=exe -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o "$output" "$helper/gate/main.go"
python3 - "$helper" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
helper, binary = map(Path, sys.argv[1:])
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
receipt = {"binarySha256": sha(binary), "sourceSha256": sha(helper / 'gate/main.go'),
           "buildRecipeSha256": sha(helper / 'gate-build.sh'),
           "go": subprocess.check_output(['go', 'version'], text=True).strip(),
           "GOOS": 'linux', "CGO_ENABLED": '0',
           "GOARCH": subprocess.check_output(['go', 'env', 'GOARCH'], text=True).strip(),
           "qualification": 'Static gate build only. Live allocator qualification is separate.'}
Path(str(binary) + '.json').write_text(json.dumps(receipt, indent=2) + '\n')
PY
