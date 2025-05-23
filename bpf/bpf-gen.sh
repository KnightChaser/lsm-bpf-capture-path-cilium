#!/usr/bin/env bash
set -euo pipefail

go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -D__TARGET_ARCH_x86 -I." \
  CaptureFileOpen capture_file_open.bpf.c

go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -D__TARGET_ARCH_x86 -I." \
  CaptureInodeRename capture_inode_rename.bpf.c
