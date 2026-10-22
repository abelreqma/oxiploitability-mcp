#!/usr/bin/env bash
# Stages one platform's MCPB bundle directory. Run from the repository root.
# Usage: mcpb/stage.sh <darwin|linux|win32> <out-dir> <binary> [<binary>...]
# Two or more binaries are merged into one universal macOS binary with lipo.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <darwin|linux|win32> <out-dir> <binary> [<binary>...]" >&2
  exit 2
fi
platform=$1
out=$2
shift 2

case "$platform" in
  darwin | linux) name=oxiploitability ;;
  win32) name=oxiploitability.exe ;;
  *)
    echo "unknown platform: $platform" >&2
    exit 2
    ;;
esac

rm -rf "$out"
mkdir -p "$out/server"

"${PYTHON:-python3}" - mcpb/manifest.json "$out/manifest.json" "$platform" "server/$name" <<'PY'
import json
import sys

source, destination, platform, entry = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    manifest = json.load(file)
manifest["compatibility"]["platforms"] = [platform]
manifest["server"]["entry_point"] = entry
with open(destination, "w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=2)
    file.write("\n")
PY
cp LICENSE-MIT LICENSE-APACHE "$out/"

if [ "$#" -gt 1 ]; then
  lipo -create -output "$out/server/$name" "$@"
else
  cp "$1" "$out/server/$name"
fi
chmod 755 "$out/server/$name"
