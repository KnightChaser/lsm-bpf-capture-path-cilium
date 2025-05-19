// main.go

package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
	"lsm-bpf-capture-path-cilium/bpf"
)

func main() {
	// bump RLIMIT_MEMLOCK so BPF maps/programs can load
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	// kick off the BPF machinery
	if err := bpf.RunCaptureFilePath(); err != nil {
		log.Fatalf("bpf.Run(): %v", err)
	}
}
