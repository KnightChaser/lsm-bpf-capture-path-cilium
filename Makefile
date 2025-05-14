# Tools
BPFTOOL     := bpftool
GO          := go
GEN_SCRIPT  := bpf-gen.sh
BTF_HEADER  := vmlinux.h
BINARY      := capture_path

.PHONY: all gen build clean

all: $(BTF_HEADER) gen build

# 1. Export kernel BTF for CO-RE
$(BTF_HEADER):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. Ensure bpf-gen.sh is executable and run go generate
gen: $(GEN_SCRIPT)
	chmod +x $(GEN_SCRIPT)
	$(GO) generate

# 3. Build Go program
build:
	$(GO) build -o $(BINARY) .


# Remove all generated artifacts
clean:
	rm -f vmlinux.h
	rm -f capturepath_bpfeb.go
	rm -f capturepath_bpfel.go
	rm -f capturepath_bpfeb.o
	rm -f capturepath_bpfel.o
	rm -f capture_path
