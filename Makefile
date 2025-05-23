# Tools
BPFTOOL     := bpftool
GO          := go
BPF_DIR     := bpf
BTF_HEADER  := vmlinux.h
BINARY      := capture_path

.PHONY: all gen build clean

all: $(BTF_HEADER) gen build

# 1. Export kernel BTF for CO-RE
$(BTF_HEADER):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/$@

# 2. Ensure bpf-gen.sh is executable and run go generate
gen: $(GEN_SCRIPT)
	chmod +x ./$(BPF_DIR)/$(GEN_SCRIPT)
	$(GO) generate ./$(BPF_DIR)

# 3. Build Go program
build:
	$(GO) build -o $(BINARY) .


# Remove all generated artifacts
clean:
	rm -f $(BPF_DIR)/$(BTF_HEADER)
	rm -f $(BINARY)
	rm -rf \
	  $(BPF_DIR)/*_bpfeb.go \
	  $(BPF_DIR)/*_bpfel.go \
	  $(BPF_DIR)/*.o
