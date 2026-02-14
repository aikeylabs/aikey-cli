#!/bin/bash
cd /Users/lautom/aikeylabs-ak
cargo build 2>&1 | tee build_output.txt
echo "Exit code: $?"
