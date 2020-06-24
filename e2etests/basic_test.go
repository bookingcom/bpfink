// +build e2e

package e2etests

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

type World struct {
	BPFink *BPFinkInstance
	t      *testing.T
}

var (
	bpfinkBinPath = flag.String("bpfink-bin", "", "ABSOLUTE path to tested bpfink binary")                             //nolint:gochecknoglobals
	ebpfObjPath   = flag.String("ebpf-obj", "", "ABSOLUTE path to tested ebpf program")                                //nolint:gochecknoglobals
	wait          = flag.Bool("wait", false, "set up environment & wait for user permission to run actual test suite") //nolint:gochecknoglobals
)

func SetUp(t *testing.T) *World {
	if *wait && !testing.Verbose() {
		t.Fatal("--wait option works only with -v (verbose) testing mode")
	}

	testRootDir, err := ioutil.TempDir("", "bpfink_test")
	if err != nil {
		t.Fatal("Can't create temp library for bpfink: ", err)
	}

	bpfink := BPFinkRun(t, BPFinkRunParameters{
		BPFinkBinPath:      *bpfinkBinPath,
		BPFinkEbpfProgramm: *ebpfObjPath,
		SandboxDir:         filepath.Join(testRootDir),
	})

	if *wait {
		fmt.Fprintf(os.Stderr, "bpfink is running with %d pid. Press Ctrl+C to run actual test...", bpfink.cmd.Process.Pid)
		resume := make(chan os.Signal, 1)
		signal.Notify(resume, syscall.SIGINT)
		<-resume
	}

	return &World{
		BPFink: bpfink,
		t:      t,
	}
}

func TearDown(w *World) {
	w.BPFink.Shutdown()
}

func TestStartRespondDie(t *testing.T) {
	world := SetUp(t)
	defer TearDown(world)
}
