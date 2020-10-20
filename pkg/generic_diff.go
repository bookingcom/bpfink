package pkg

import (
	"github.com/bookingcom/bpfink/pkg/lang/genericdiff"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
)

type (
	//GenericDiff struct used to store changes to the generic file with diff
	GenericDiff struct {
		Rule []string
	}

	//GenericDiffListener struct used for filestream events.
	GenericDiffListener struct {
		zerolog.Logger
		afero.Fs
		genericDiff string
	}

	genericDiffListener struct {
		GenericDiff
		zerolog.Logger
	}
)

func findGenericDiff(old, new GenericDiff) (add, del GenericDiff) {
	add, del = GenericDiff{}, GenericDiff{}
	add.Rule, del.Rule = ArrayDiff(old.Rule, new.Rule)
	return
}

//IsEmpty method to check if diff is empty
func (gd GenericDiff) IsEmpty() bool { return len(gd.Rule) == 0 }

//GenericDiffFileOpt function used to return metadata on a file
func GenericDiffFileOpt(fs afero.Fs, path string, logger zerolog.Logger) func(*GenericDiffListener) {
	return func(listener *GenericDiffListener) {
		listener.genericDiff = path
		listener.Logger = logger
		listener.Fs = fs
	}
}

//NewGenericDiffListener function to create a new file event listener
func NewGenericDiffListener(options ...func(*GenericDiffListener)) *GenericDiffListener {
	gdl := &GenericDiffListener{Logger: zerolog.Nop()}
	for _, option := range options {
		option(gdl)
	}
	return gdl
}

func (gdl *GenericDiffListener) parse() (GenericDiff, error) {
	listener := &genericDiffListener{Logger: gdl.Logger}
	gdl.Debug().Msgf("parsing critical generic file: %v", gdl.genericDiff)

	err := listener.genericDiffParse(gdl.genericDiff)
	if err != nil {
		return GenericDiff{}, err
	}
	return listener.GenericDiff, nil
}

func (gdl *genericDiffListener) genericDiffParse(fileName string) error {
	genericDiffData := genericdiff.Parser{FileName: fileName, Logger: gdl.Logger}
	err := genericDiffData.Parse()
	if err != nil {
		return err
	}
	for _, genericDiffdata := range genericDiffData.GenericDiff {
		gdl.GenericDiff.Rule = append(gdl.GenericDiff.Rule, genericDiffdata.Rule)
	}
	return nil
}

//Register method returns list of paths to files to be watched
func (gdl *GenericDiffListener) Register() []string {
	if base, ok := gdl.Fs.(*afero.BasePathFs); ok {
		path, _ := base.RealPath(gdl.genericDiff)
		return []string{path}
	}
	return []string{gdl.genericDiff}
}
