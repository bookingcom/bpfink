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

}

func testCreateGenericFile(t *testing.T, w *World) {
	genericFile := path.Join(w.FS.GenericMonitoringDir, "hohoho.txt")
	f := w.FS.MustCreateFile(t, genericFile)
	w.BPFink.ExpectGenericEvent(t, Event{
		File:    genericFile,
		Message: "generic file created",
	})

	f.WriteString("hello world")
	w.BPFink.ExpectGenericEvent(t, Event{
		File:    genericFile,
		Message: "generic file Modified",
	})

	w.FS.MustRemoveFile(t, genericFile)
	w.BPFink.ExpectGenericEvent(t, Event{
		File:    genericFile,
		Message: "generic file deleted",
	})
}
