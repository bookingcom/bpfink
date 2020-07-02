// +build e2e

package e2etests

import (
	"path"
	"testing"
)

func TestBPfink(t *testing.T) {
	world := SetUp(t)
	defer world.TearDown()
	t.Run("generic file create/modify/delete", world.SubTest(testCreateGenericFile))
	t.Run("sudoers file create", world.SubTest(testCreateSudoersDir))

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

func testCreateSudoersDir(t *testing.T, w *World) {
	sudoersFile := path.Join(w.FS.SudoersDir, "testSudoers")
	f := w.FS.MustCreateFile(t, sudoersFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    sudoersFile,
		Message: "Sudoers file created",
	})
	f.WriteString("root ALL=(ALL) ALL")
	w.BPFink.ExpectEvent(t, Event{
		File:    sudoersFile,
		Message: "Sudoers file modified",
	})

	w.FS.MustRemoveFile(t, sudoersFile)
	w.BPFink.ExpectEvent(t, Event{
		File:    sudoersFile,
		Message: "Sudoers file deleted",
	})
}
