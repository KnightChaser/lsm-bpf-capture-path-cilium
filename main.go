//go:generate ./bpf-gen.sh

// main.go
package main

import (
	"C"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event mirrors the kernel’s struct event layout.
type Event struct {
	PID           uint32
	FileOpenerUID uint32
	FileOpenerGID uint32
	FileOwnerUID  uint32
	FileOwnerGID  uint32
	Mode          uint32
	Inode         uint64
	Size          uint64
	ProcessName   [32]byte
	Path          [384]byte
}

// cStr converts a null-terminated byte array to a Go string.
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func main() {
	// Remove memory lock
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	// Load and attach generated objects
	var objs CapturePathObjects
	if err := LoadCapturePathObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	// Attach the LSM hook
	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.CaptureOpen,
	})
	if err != nil {
		log.Fatalf("attach LSM: %v", err)
	}
	defer lsmLink.Close()

	// Open the ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	// Handle shtudown (gracefuly)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Listening to events (Ctrl-C to stop)...")

	for {
		select {
		case <-sig:
			log.Println("Received signal, exiting...")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					log.Println("ringbuf closed")
					return
				}
				log.Printf("ringbuf read error: %v", err)
				continue
			}

			// Decode and process the event
			var e Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding event: %v", err)
				continue
			}

			// Resolve UIDs/GIDs to names
			openerUser, err := user.LookupId(strconv.Itoa(int(e.FileOpenerUID)))
			openerName := strconv.Itoa(int(e.FileOpenerUID))
			if err == nil {
				openerName = openerUser.Username
			}
			openerGroup, err := user.LookupGroupId(strconv.Itoa(int(e.FileOpenerGID)))
			openerGroupName := strconv.Itoa(int(e.FileOpenerGID))
			if err == nil {
				openerGroupName = openerGroup.Name
			}

			ownerUser, err := user.LookupId(strconv.Itoa(int(e.FileOwnerUID)))
			ownerName := strconv.Itoa(int(e.FileOwnerUID))
			if err == nil {
				ownerName = ownerUser.Username
			}
			ownerGroup, err := user.LookupGroupId(strconv.Itoa(int(e.FileOwnerGID)))
			ownerGroupName := strconv.Itoa(int(e.FileOwnerGID))
			if err == nil {
				ownerGroupName = ownerGroup.Name
			}

			// Print formatted event
			fmt.Printf(
				"[PID %d] Opener=%s(%d):%s(%d), Owner=%s(%d):%s(%d), inode=%d, size=%d, mode=%#o, proc=%s, path=%s\n",
				e.PID,
				openerName, e.FileOpenerUID, openerGroupName, e.FileOpenerGID,
				ownerName, e.FileOwnerUID, ownerGroupName, e.FileOwnerGID,
				e.Inode, e.Size, e.Mode&0xFFF,
				cStr(e.ProcessName[:]), cStr(e.Path[:]),
			)
		}
	}
}
