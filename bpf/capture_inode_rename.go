//go:generate ./bpf-gen.sh

// bpf/capture_inode_rename.go

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	PID     uint32
	UID     uint32
	GID     uint32
	Comm    [32]byte
	OldPath [384]byte
	NewPath [384]byte
}

// RunCaptureInodeRename sets up the BPF probe and prints rename events.
func RunCaptureInodeRename() error {
	// Load compiled BPF objects
	var objs CaptureInodeRenameObjects
	if err := LoadCaptureInodeRenameObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach to inode_rename LSM hook
	lnk, err := link.AttachLSM(link.LSMOptions{
		Program: objs.CaptureRename,
	})
	if err != nil {
		return fmt.Errorf("attach LSM inode_rename: %w", err)
	}
	defer lnk.Close()

	// Open ring buffer reader on map "events"
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf.NewReader: %w", err)
	}
	defer rd.Close()

	// Handle SIGINT/SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Channel to receive decoded events
	events := make(chan event)

	// Reader goroutine
	go func() {
		defer close(events)
		for {
			select {
			case <-sigCh:
				rd.Close()
				return
			default:
				rec, err := rd.Read()
				if err != nil {
					if err == ringbuf.ErrClosed {
						return
					}
					log.Printf("ringbuf read error: %v", err)
					continue
				}
				var e event
				if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
					log.Printf("binary.Read error: %v", err)
					continue
				}
				events <- e
			}
		}
	}()

	// Main loop: print rename events
	for e := range events {
		oldPath := string(bytes.TrimRight(e.OldPath[:], "\x00"))
		newPath := string(bytes.TrimRight(e.NewPath[:], "\x00"))
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		fmt.Printf("[PID %d UID %d GID %d COMM %s] %s → %s\n",
			e.PID, e.UID, e.GID, comm, oldPath, newPath)
	}

	return nil
}
