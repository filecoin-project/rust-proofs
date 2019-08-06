#!/usr/bin/env bash

set -e

CMDS=$(cat <<EOF
cd \$(mktemp -d)
git clone -q https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q master
RUSTFLAGS="-Awarnings -C target-cpu=native" /root/.cargo/bin/cargo run --quiet --bin micro --release ${@:2}
EOF
)

ssh -q $1 "$CMDS"
