package e2etests

import (
	"os"
	"testing"
)

type FS struct {
	GenericMonitoringDir string
	SudoersDir           string
}

func (fs *FS) MustCreateFile(t *testing.T, filePath string) *os.File {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_EXCL|os.O_SYNC, 0666)
	if err != nil {
		t.Fatalf("unable to create file %s: %s", filePath, err)
	}

	return f
}

func (fs *FS) MustCreateDir(t *testing.T, dirPath string) {
	err := os.MkdirAll(dirPath, 0666)
	if err != nil {
		t.Fatalf("unable to create directory %s: %s", dirPath, err)
	}
}

func (fs *FS) MustRemoveFile(t *testing.T, filePath string) {
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("unable to remove file %s: %s", filePath, err)
	}
}
