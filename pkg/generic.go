package pkg

import (
	"github.com/bookingcom/bpfink/pkg/lang/generic"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
)

type (
	//Generic struct used to store changes to generic files
	Generic struct {
		Contents []byte
	}
	//GenericListener struct used for filestream events.
	GenericListener struct {
		zerolog.Logger
		afero.Fs
		File  string
		IsDir bool
		Key   []byte
	}
	genericListener struct {
		Generic
		zerolog.Logger
	}
)

//IsEmpty method to check if diff is empty
func (a Generic) IsEmpty() bool { return len(a.Contents) == 0 }

//GenericFileOpt function used to return metadata on a file
func GenericFileOpt(fs afero.Fs, path string, logger zerolog.Logger) func(*GenericListener) {
	return func(listener *GenericListener) {
		listener.Fs = NewFile(func(file *File) {
			file.Fs, file.Path, file.Logger = fs, path, logger
		})
		listener.File = path
		listener.Logger = logger
	}
}

//NewGenericListener function to create a new file event listener
func NewGenericListener(options ...func(*GenericListener)) *GenericListener {
	gl := &GenericListener{Logger: zerolog.Nop()}
	for _, option := range options {
		option(gl)
	}
	return gl
}

func (gl *GenericListener) parse() (Generic, error) {
	listener := &genericListener{Logger: gl.Logger}
	gl.Debug().Msgf("parsing access: %v", gl.File)
	if gl.IsDir {
		return Generic{}, nil
	}
	gl.Debug().Msgf("parsing access: %v", gl.File)
	err := listener.genericParse(gl.File, gl.Key)
	if err != nil {
		return Generic{}, err
	}
	return listener.Generic, nil
}

func (gl *genericListener) genericParse(fileName string, key []byte) error {
	genericData := generic.Parser{FileName: fileName, Logger: gl.Logger, Key: key}
	err := genericData.Parse()
	if err != nil {
		return err
	}
	gl.Generic.Contents = genericData.Hash
	return nil
}

//Register method returns list of paths to files to be watched
func (gl *GenericListener) Register() []string {
	return []string{gl.File}
}
