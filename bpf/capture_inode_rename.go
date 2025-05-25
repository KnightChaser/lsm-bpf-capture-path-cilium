//go:generate ./bpf-gen.sh

// bpf/capture_inode_rename.go

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	SENTINEL_DEPTH       = ^uint32(0) // math.MaxUint32
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

type pathPair struct {
	oldFrags        []renamePathFragEvent // Fragments of the old path
	newFrags        []renamePathFragEvent // Fragments of the new path
	oldFragsAreDone bool                  // Fragments of the old path are all received
	newFragsAreDone bool                  // Fragments of the new path are all received
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

	go func() {
		<-sigCh
		rd.Close()
	}()

	// Map to store path pairs
	pairs := make(map[uint64]*pathPair)

	// Reader goroutine
	for {
		rec, err := rd.Read()
		if err != nil {
			// detect real closure of the ring buffer
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		var f renamePathFragEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &f); err != nil {
			log.Printf("binary.Read error: %v", err)
			continue
		}

		// get or create the new path pair
		p := pairs[f.EventID]
		if p == nil {
			p = &pathPair{
				oldFrags:        make([]renamePathFragEvent, 0),
				newFrags:        make([]renamePathFragEvent, 0),
				oldFragsAreDone: false,
				newFragsAreDone: false,
			}
			pairs[f.EventID] = p
		}

		// sentinel?
		if f.Depth == SENTINEL_DEPTH {
			if f.OldOrNew == 0 {
				p.oldFragsAreDone = true
			} else {
				p.newFragsAreDone = true
			}
		} else {
			if f.OldOrNew == 0 {
				p.oldFrags = append(p.oldFrags, f)
			} else {
				p.newFrags = append(p.newFrags, f)
			}
		}

		// Only when both old and new paths are done,
		// we can proceed to print the pair
		if p.oldFragsAreDone && p.newFragsAreDone {
			printPair(p.oldFrags, p.newFrags)
			delete(pairs, f.EventID)
		}

	}

	<-sigCh
	return nil
}

func printPair(oldList, newList []renamePathFragEvent) {
	sort.Slice(oldList,
		func(i, j int) bool {
			return oldList[i].Depth > oldList[j].Depth
		},
	)
	sort.Slice(newList,
		func(i, j int) bool {
			return newList[i].Depth > newList[j].Depth
		},
	)

	build := func(list []renamePathFragEvent) string {
		parts := make([]string, len(list))
		for i, f := range list {
			parts[i] = string(bytes.TrimRight(f.DName[:], "\x00"))
		}
		return "/" + strings.Join(parts, "/")
	}

	oldPath := build(oldList)
	newPath := build(newList)
	meta := newList[0] // or oldList[0], both have same meta
	comm := string(bytes.TrimRight(meta.Comm[:], "\x00"))

	fmt.Printf("[PID %d UID %d GID %d COMM %s] %s -> %s\n",
		meta.PID, meta.UID, meta.GID, comm, oldPath, newPath)
}
