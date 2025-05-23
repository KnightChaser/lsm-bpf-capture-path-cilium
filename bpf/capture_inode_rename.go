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
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	MAX_NAME_LEN         = 384
	MAX_PROCESS_NAME_LEN = 32
)

type renamePathFragEvent struct {
	EventID  uint64
	PID      uint32
	UID      uint32
	GID      uint32
	Comm     [MAX_PROCESS_NAME_LEN]byte
	OldOrNew uint32
	Depth    uint32
	DName    [MAX_NAME_LEN]byte
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
	rd, err := ringbuf.NewReader(objs.FragBuf)
	if err != nil {
		return fmt.Errorf("ringbuf.NewReader: %w", err)
	}
	defer rd.Close()

	// Handle SIGINT/SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	type key struct {
		id       uint64
		oldOrNew uint32
	}
	frags := make(map[key][]renamePathFragEvent)

	// Reader goroutine
	go func() {
		defer rd.Close()
		for {
			rec, err := rd.Read()
			if err == ringbuf.ErrClosed {
				return
			} else if err != nil {
				log.Printf("ringbuf read error: %v", err)
				continue
			}

			var f renamePathFragEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &f); err != nil {
				log.Printf("binary.Read error: %v", err)
				continue
			}

			k := key{f.EventID, f.OldOrNew}
			frags[k] = append(frags[k], f)

			// simple flush: once we see >2 fragments, assemble
			if len(frags[k]) > 2 {
				go assembleAndPrint(frags[k])
				delete(frags, k)
			}
		}
	}()

	<-sigCh
	return nil
}

func assembleAndPrint(list []renamePathFragEvent) {
	// sort by depth descending (leaf first)
	sort.Slice(list, func(i, j int) bool {
		return list[i].Depth > list[j].Depth
	})

	parts := make([]string, 0, len(list))
	for _, f := range list {
		name := string(bytes.TrimRight(f.DName[:], "\x00"))
		parts = append(parts, name)
	}
	full := "/" + strings.Join(parts, "/")

	kind := "OLD"
	if list[0].OldOrNew == 1 {
		kind = "NEW"
	}
	meta := list[0]
	comm := string(bytes.TrimRight(meta.Comm[:], "\x00"))
	fmt.Printf("[PID %d UID %d GID %d COMM %s] %s -> %s\n",
		meta.PID, meta.UID, meta.GID, comm, kind, full)
}
