package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/elastic/go-perf"
)

type EventDigest struct {
	PyStack string
	User    bool
	Rip     uint64
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpf bpf ./bpf.c -- -I../bpf_headers -I. -Wall
func main() {
	targetPid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("failed to parse pid: %v", err)
	}

	obj := &bpfObjects{}
	if err := loadBpfObjects(obj, nil); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}

	pfa := &perf.Attr{}
	perf.CPUClock.Configure(pfa)
	pfa.SetSampleFreq(99)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pe, err := perf.Open(pfa, targetPid, perf.AnyCPU, nil)
	if err != nil {
		log.Fatalf("failed to open perf event: %v", err)
	}

	if err := pe.SetBPF(uint32(obj.PerfEventCpython310.FD())); err != nil {
		log.Fatalf("failed to set bpf program: %v", err)
	}
	defer pe.Close()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Profiling, press ctrl+c to exit...")

	eventsReader, err := ringbuf.NewReader(obj.Ringbuf)
	if err != nil {
		log.Printf("Failed to open ringbuf: %+v", err)
	}
	defer eventsReader.Close()

	go func() {
		<-done
		eventsReader.Close()
	}()

	digestStats := map[EventDigest]uint64{}

	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Failed to read ringbuf: %+v", err)
			continue
		}

		var event bpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse ringbuf event: %+v", err)
			continue
		}

		eventDigest := EventDigest{
			User: event.UserMode == 1,
			Rip:  event.Rip,
		}

		if event.PythonStackDepth >= 0 {
			stackframes := []string{}
			for i := 0; i <= int(event.PythonStackDepth); i++ {
				stackframes = append(stackframes, fmt.Sprintf("%s:%s",
					string(event.Filename[i][:event.FilenameLen[i]]),
					string(event.Funcname[i][:event.FuncnameLen[i]])))
			}
			eventDigest.PyStack = strings.Join(stackframes, "\n")
		}

		digestStats[eventDigest]++
	}

	digests := []EventDigest{}
	for digest := range digestStats {
		digests = append(digests, digest)
	}

	sort.Slice(digests, func(i, j int) bool {
		return digestStats[digests[i]] < digestStats[digests[j]]
	})

	for _, digest := range digests {
		fmt.Printf("%+v: %d\n\n", digest, digestStats[digest])
	}

}
