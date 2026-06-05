#!/usr/bin/env bash
# Build the `svault` CLI and stage it as a Tauri sidecar so one desktop installer
# also delivers the CLI + TUI + MCP. Tauri resolves `externalBin` entries with a
# target-triple suffix, so the staged file is named `svault-<triple>`.
#
# Usage:  scripts/bundle-sidecar.sh
# Then add  "externalBin": ["binaries/svault"]  under `bundle` in
# gui/src-tauri/tauri.conf.json before `npm run tauri build`.
set -euo pipefail

cd "$(dirname "$0")/.."

triple="$(rustc -vV | awk '/host:/ {print $2}')"
ext=""
case "$triple" in
  *windows*) ext=".exe" ;;
esac

echo "Building svault (release) for $triple…"
cargo build --release --bin svault

dest_dir="gui/src-tauri/binaries"
mkdir -p "$dest_dir"
cp "target/release/svault${ext}" "${dest_dir}/svault-${triple}${ext}"

echo "Staged ${dest_dir}/svault-${triple}${ext}"
echo "Add  \"externalBin\": [\"binaries/svault\"]  to tauri.conf.json's bundle section."
