BPFTOLL      := bpftool
CC           := clang
CFLAGS       := -O2 -g -target bpf -I.
GO           := go

# Default target: generate BTF header, compile BPF, build Go binary
all: vmlinux.h capture_path.bpf.o capture_path

# 1. Generate the kernel type header for CO-RE
vmlinux.h:
	$(BPFTOLL) btf dump file /sys/kernel/btf/vmlinux format c > $@ 

# 2. Compile the BPF stub into an object
capture_path.bpf.o: capture_path.bpf.c vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ 

# 3. Build the Go loader program
capture_path: main.go
	$(GO) build -o $@ .

# Clean up intermediate and binary files
clean:
	rm -f vmlinux.h 
	rm -f capture_path.bpf.o 
	rm -f capture_path

