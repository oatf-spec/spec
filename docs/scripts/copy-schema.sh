#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p public/schemas
cp ../schemas/v0.1.json public/schemas/v0.1.json
