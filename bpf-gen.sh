#!/usr/bin/env bash
set -euo pipefail

go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -D__TARGET_ARCH_x86 -I." \
  CapturePath capture_path.bpf.c
