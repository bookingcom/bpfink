package pkg

import (
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/bookingcom/bpfink/pkg/lang/sudoers"
)

type (
	//Sudoers struct used to store changes to the sudoers file
	Sudoers struct {
        Rule []string
	}

	//SudoersListener struct used for filestream events.
	SudoersListener struct {
		zerolog.Logger
		afero.Fs
		sudoers string
	}

	sudoersListener struct {
		Sudoers
		zerolog.Logger
	}
)

func sudoersDiff(old, new Sudoers) (add, del Sudoers) {
	add, del = Sudoers{}, Sudoers{}
	add.Rule, del.Rule = ArrayDiff(old.Rule, new.Rule)
	return
}

//IsEmpty method to check if diff is empty
func (s Sudoers) IsEmpty() bool { return len(s.Rule) == 0 }

//SudoersFileOpt function used to return metadata on a file
func SudoersFileOpt(fs afero.Fs, path string, logger zerolog.Logger) func(*SudoersListener) {
	return func(listener *SudoersListener) {
		listener.Fs = NewFile(func(file *File) {
			file.Fs, file.Path, file.Logger = fs, path, logger
		})
		listener.sudoers = path
		listener.Logger = logger
	}
}

//NewSudoersListener function to create a new file event listener
func NewSudoersListener(options ...func(*SudoersListener)) *SudoersListener {
	sl := &SudoersListener{Logger: zerolog.Nop()}
	for _, option := range options {
		option(sl)
	}
	return sl
}

func (sl *SudoersListener) parse() (Sudoers, error) {
	listener := &sudoersListener{Logger: sl.Logger}
	sl.Debug().Msgf("parsing sudoers: %v", sl.sudoers)

	err := listener.sudoersParse(sl.sudoers)
	if err != nil {
		return Sudoers{}, err
	}
	return listener.Sudoers, nil
}

func (sl *sudoersListener) sudoersParse(fileName string) error {
	sudoersData := sudoers.Parser{FileName: fileName, Logger: sl.Logger}
	err := sudoersData.Parse()
	if err != nil {
		return err
	}
	sl.Debug().Msg("parsing sudoers file")
	for _, sudoersdata := range sudoersData.Sudoers {
		sl.Sudoers.Rule = append(sl.Sudoers.Rule, sudoersdata.User)
	}
	return nil
}

//Register method returns list of paths to files to be watched
func (sl *SudoersListener) Register() []string {
	if base, ok := sl.Fs.(*afero.BasePathFs); ok {
		path, _ := base.RealPath(sl.sudoers)
		return []string{path}
	}
	return []string{sl.sudoers}
}




