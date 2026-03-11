#!/usr/bin/env bash
set -euo pipefail

# Copy the JSON Schema into the public directory
mkdir -p public/schemas
cp ../schemas/v0.1.json public/schemas/v0.1.json

# Copy the docs tree into src/content/docs (replaces the former symlink).
# Using a real copy avoids the duplicate-ID warnings that Starlight's content
# loader emits when the docs directory is a symlink and Vite's
# preserveSymlinks option is enabled.
rm -rf src/content/docs
mkdir -p src/content/docs
rsync -a --delete ../docs/ src/content/docs/
