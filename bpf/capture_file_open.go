//go:generate ./bpf-gen.sh

// bpf/capture_file_path.go

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"lsm-bpf-capture-path-cilium/utilities"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Event mirrors the kernel’s struct event layout.
type Event struct {
	PID               uint32
	FileOpenerUID     uint32
	FileOpenerGID     uint32
	FileOwnerUID      uint32
	FileOwnerGID      uint32
	Mode              uint32
	Fmode             uint32
	FileOperationType uint32
	Inode             uint64
	Size              uint64
	ProcessName       [32]byte
	Path              [384]byte
}

// cStr turns a null-terminated byte array into a Go string.
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func RunCaptureFilePath() error {
	// load generated BPF assets
	var objs CaptureFileOpenObjects
	if err := LoadCaptureFileOpenObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	defer objs.Close()

	// attach the LSM hook
	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.CaptureOpen,
	})
	if err != nil {
		return fmt.Errorf("attach LSM: %w", err)
	}
	defer lsmLink.Close()

	// open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf NewReader: %w", err)
	}
	defer rd.Close()

	// catch SIGINT/SIGTERM to exit cleanly
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// channel of decoded events
	events := make(chan Event)

	// reader goroutine
	go func() {
		defer close(events)
		for {
			select {
			case <-sig:
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

				var e Event
				if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
					log.Printf("decoding event: %v", err)
					continue
				}
				events <- e
			}
		}
	}()

	// main logging loop
	for e := range events {
		openerName := utilities.LookupUserName(e.FileOpenerUID)
		openerGroup := utilities.LookupGroupName(e.FileOpenerGID)
		ownerName := utilities.LookupUserName(e.FileOwnerUID)
		ownerGroup := utilities.LookupGroupName(e.FileOwnerGID)
		opTypeMap := map[uint32]string{0: "READ", 1: "WRITE", 2: "OTHER"}
		opTypeStr := opTypeMap[e.FileOperationType]

		log.Printf(
			"[PID %d] Opener=%s(%d):%s(%d), Owner=%s(%d):%s(%d), inode=%d, size=%d, mode=%#o, proc=%s, path=%s, fmode=0b%032b, op=%d(%s)",
			e.PID,
			openerName, e.FileOpenerUID, openerGroup, e.FileOpenerGID,
			ownerName, e.FileOwnerUID, ownerGroup, e.FileOwnerGID,
			e.Inode, e.Size, e.Mode&0xFFF,
			cStr(e.ProcessName[:]), cStr(e.Path[:]),
			e.Fmode, e.FileOperationType, opTypeStr,
		)
	}

	return nil
}
