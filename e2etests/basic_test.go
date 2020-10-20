// +build e2e

package e2etests

import (
	"path"
	"testing"
	"time"
)

func TestBPfink(t *testing.T) {
	world := SetUp(t)
	defer world.TearDown()
	t.Run("generic file create/modify/delete", world.SubTest(testCreateGenericFile))
	t.Run("generic file with diff create/modify/delete", world.SubTest(testCreateGenericDiffFile))
	t.Run("generic file in newly created dir", world.SubTest(testCreateDirectory))

}

func testCreateGenericFile(t *testing.T, w *World) {
	genericFile := path.Join(w.FS.GenericMonitoringDir, "hohoho.txt")
	f := w.FS.MustCreateFile(t, genericFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    genericFile,
		Message: "generic file created",
	})

	f.WriteString("hello world")
	w.BPFink.ExpectEvent(t, Event{
		File:    genericFile,
		Message: "generic file Modified",
	})
	w.FS.MustRemoveFile(t, genericFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    genericFile,
		Message: "generic file deleted",
	})
}

func testCreateGenericDiffFile(t *testing.T, w *World) {
	genericDiffFile := path.Join(w.FS.GenericMonitoringDir, "test-generic", "test-generic-diff.txt")
	f := w.FS.MustCreateFile(t, genericDiffFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    genericDiffFile,
		Message: "Critical Generic file created",
	})
	f.WriteString("root ALL=(ALL) ALL")
	w.BPFink.ExpectEvent(t, Event{
		File:    genericDiffFile,
		Message: "Critical Generic file modified",
	})

	w.FS.MustRemoveFile(t, genericDiffFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    genericDiffFile,
		Message: "Critical Generic file deleted",
	})
}

func testCreateDirectory(t *testing.T, w *World) {
	dirToCreate := path.Join(w.FS.GenericMonitoringDir, "dir1")
	w.FS.MustCreateDir(t, dirToCreate)

	// TODO: bpfink can't process dir creation + file creation immediately
	// need some time to handle dir creation properly
	time.Sleep(100 * time.Millisecond)
	fileToCreate := path.Join(dirToCreate, "sample_file.txt")
	f := w.FS.MustCreateFile(t, fileToCreate)
	w.BPFink.ExpectEvent(t, Event{
		File:    fileToCreate,
		Message: "generic file created",
	})

	f.WriteString("hello world")
	w.BPFink.ExpectEvent(t, Event{
		File:    fileToCreate,
		Message: "generic file Modified",
	})
	w.FS.MustRemoveFile(t, fileToCreate)
	w.BPFink.ExpectEvent(t, Event{
		File:    fileToCreate,
		Message: "generic file deleted",
	})

	// TODO this exceptation is failing with 'failed to remove consumer' log line
	// w.FS.MustRemoveFile(t, dirToCreate)
	// time.Sleep(100 * time.Millisecond)
	// w.BPFink.ExpectNothing(t)
}
