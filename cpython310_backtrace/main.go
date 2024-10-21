package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
	println("Target PID:", targetPid)

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
	perf.CPUCycles.Configure(pfa)
	pfa.SetSampleFreq(99)
	pfa.Options.Inherit = true
	pfa.Options.SampleIDAll = true
	pfa.SampleFormat.Tid = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	threadIDs, err := listThreadIDs(targetPid)
	if err != nil {
		log.Fatalf("failed to list thread IDs: %v", err)
	}
	for _, threadID := range threadIDs {
		println("Thread ID:", threadID)
		pe, err := perf.Open(pfa, threadID, perf.AnyCPU, nil)
		if err != nil {
			log.Fatalf("failed to open perf event: %v", err)
		}
		if err := pe.SetBPF(uint32(obj.PerfEventCpython310.FD())); err != nil {
			log.Fatalf("failed to set bpf program: %v", err)
		}
		defer pe.Close()
	}

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

func listThreadIDs(pid int) ([]int, error) {
	// Define the path to the /proc/[PID]/task directory
	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")

	// Open the task directory to read its contents
	files, err := ioutil.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("could not read task directory: %v", err)
	}

	// Iterate through the directory contents and collect thread IDs
	var threadIDs []int
	for _, file := range files {
		if file.IsDir() {
			tid, err := strconv.Atoi(file.Name())
			if err == nil {
				threadIDs = append(threadIDs, tid)
			}
		}
	}

	return threadIDs, nil
}
