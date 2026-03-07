#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
{
  echo "# OATF — Open Agent Threat Format"
  echo ""
  echo "# Part 1: Format Specification"
  echo ""
  cat ../spec/format.md
  echo ""
  echo ""
  echo "# Part 2: SDK Specification"
  echo ""
  cat ../spec/sdk.md
} > public/llms-full.txt
