#!/usr/bin/env bash
# Compile target.c for use with the obfuscator.
# Run from the pj/ directory:
#   bash build_target.sh
set -e
gcc -o target target.c -no-pie -fno-stack-protector -g
echo "Built: target"
file target
