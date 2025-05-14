// main.go
package main

import (
	"C"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

func main() {
	// Parse the ELF into a CollectionSpec
	spec, err := ebpf.LoadCollectionSpec("capture_path.bpf.o")
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	// Load all programs & maps into the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("load collection: %v", err)
	}
	defer coll.Close()

	// Grab our LSM program and ringbuf map
	prog := coll.Programs["capture_open"]
	eventsMap := coll.Maps["events"]

	fmt.Printf("Loaded program FD=%d, map FD=%d\n", prog.FD(), eventsMap.FD())
}
