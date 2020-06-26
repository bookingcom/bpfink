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

var executionParams = struct { // nolint gochecknoglobals
	bpfinkBinPath *string
	ebpfObjPath   *string
	wait          *bool
}{
	flag.String("bpfink-bin", "", "ABSOLUTE path to tested bpfink binary"),
	flag.String("ebpf-obj", "", "ABSOLUTE path to tested ebpf program"),
	flag.Bool("wait", false, "set up environment & wait for user permission to run actual test suite"),
}

type World struct {
	BPFink *BPFinkInstance
	FS     *FS
}

func SetUp(t *testing.T) *World {
	if *executionParams.wait && !testing.Verbose() {
		t.Fatal("--wait option works only with -v (verbose) testing mode")
	}

	testRootDir, err := ioutil.TempDir("", "bpfink_test")
	if err != nil {
		t.Fatal("Can't create temp library for bpfink: ", err)
	}

	bpfinkParams := BPFinkRunParameters{
		BPFinkBinPath:      *executionParams.bpfinkBinPath,
		BPFinkEbpfProgramm: *executionParams.ebpfObjPath,
		TestRootDir:        filepath.Join(testRootDir),
		GenericMonitoringDir:         filepath.Join(testRootDir, "root"),
	}

	bpfink := BPFinkRun(t, bpfinkParams)

	if *executionParams.wait {
		fmt.Fprintf(os.Stderr, "bpfink is running with %d pid. Press Ctrl+C to run actual test...", bpfink.cmd.Process.Pid)
		resume := make(chan os.Signal, 1)
		signal.Notify(resume, syscall.SIGINT)
		<-resume
	}

	return &World{
		BPFink: bpfink,
		FS: &FS{
			GenericMonitoringDir: bpfinkParams.GenericMonitoringDir,
		},
	}
}

func (w *World) TearDown() {
	w.BPFink.Shutdown()
}

func (w *World) SubTest(testFunc func(*testing.T, *World)) func(*testing.T) {
	return func(st *testing.T) {
		testFunc(st, w)
	}
}
