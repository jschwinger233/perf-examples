package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/elastic/go-perf"
	"golang.org/x/sys/unix"
)

type profile struct {
	fd int
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpf bpf ./bpf.c -- -I../bpf_headers -I. -Wall
func main() {
	targetPid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("failed to parse pid: %v", err)
	}

	obj := &bpfObjects{}
	if err := loadBpfObjects(obj, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
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

	perfFd, err := pe.FD()
	if err != nil {
		log.Fatalf("failed to get perf event fd: %v", err)
	}
	if err = unix.IoctlSetInt(perfFd, unix.PERF_EVENT_IOC_SET_BPF, obj.BpfProg1.FD()); err != nil {
		log.Fatalf("failed to attach bpf program to perf event: %v", err)
	}

	if err = pe.Enable(); err != nil {
		log.Fatalf("failed to enable perf event: %v", err)
	}
	defer pe.Close()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Profiling, press ctrl+c to exit...")
	<-done
}
