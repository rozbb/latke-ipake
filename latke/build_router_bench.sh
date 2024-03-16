#!/bin/sh

# Build a benchmark for an ARM Cortex-A53
# This requires the aarch64 musl target to be installed:
#     rustup target add aarch64-unknown-linux-musl
# It also requires a musl cross compiler, which can be set up on macOS using this repo
#     https://github.com/FiloSottile/homebrew-musl-cross
# The change to the cargo config is necessary.

cargo bench --no-run --target aarch64-unknown-linux-musl -- -C target-cpu=cortex-a53 -C --target-feature=-neon,-sha2
