package pkg

import (
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/bookingcom/bpfink/pkg/lang/sudoers"
)

type (
	//Sudoers struct used to store changes to the sudoers file
	Sudoers struct {
		RuleType string
		RuleKey string
		RuleValue []string
	}

	Sudoer map[string]*Sudoers

	//SudoersListener struct used for filestream events.
	SudoersListener struct {
		zerolog.Logger
		afero.Fs
		sudoers string
	}

	sudoersListener struct {
		Sudoer map[string]*Sudoers
		zerolog.Logger
	}
)

/*func sudoersDiff(old, new Sudoers) (add, del Sudoers) {
	add, del = Sudoers{}, Sudoers{}
	add.Rule, del.Rule = ArrayDiff(old.Rule, new.Rule)
	return
}

//IsEmpty method to check if diff is empty
func (s Sudoers) IsEmpty() bool { return len(s.Rule) == 0 }
*/

func (s1 *Sudoers) Equal(s2 *Sudoers) bool {
	return s1.RuleType == s2.RuleType && s1.RuleKey == s2.RuleKey && ArrayEqual(s1.RuleValue, s2.RuleValue)
}

func sudoersDiff(old, new Sudoer) (add, del Sudoer) {
	add, del = Sudoer{}, Sudoer{}
	for k, v := range new {
		add[k] = v
	}
	for k, v := range old {
		del[k] = v
	}
	for k, v1 := range add {
		if v2, ok := del[k]; ok && v1.Equal(v2) {
			delete(add, k)
			delete(del, k)
		}
	}
	return
}

//SudoersFileOpt function used to return metadata on a file
func SudoersFileOpt(fs afero.Fs, path string, logger zerolog.Logger) func(*SudoersListener) {
	return func(listener *SudoersListener) {
		listener.sudoers = path
		listener.Logger = logger
		listener.Fs = fs
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

func (sl *SudoersListener) parse() (map[string]*Sudoers, error) {
	listener := &sudoersListener{Logger: sl.Logger}
	sl.Debug().Msgf("parsing sudoers: %v", sl.sudoers)

	err := listener.sudoersParse(sl.sudoers)
	if err != nil {
		return nil, err
	}
	sl.Debug().Msgf("Sudoers: %v",listener.Sudoer)
	return listener.Sudoer, nil
}

func (sl *sudoersListener) sudoersParse(fileName string) error {
	sudoersData := sudoers.Parser{FileName: fileName, Logger: sl.Logger}
	sl.Debug().Msg("parsing sudoers file")
	err := sudoersData.Parse()
	if err != nil {
		return err
	}
/*
	if sudoersData.Sudoers != nil {
		for _, sudoersdata := range sudoersData.Sudoers {
			sudoersString := []string{sudoersdata.RuleType, sudoersdata.RuleKey, sudoersdata.RuleValue}
			sudoersCombined := strings.Join(sudoersString, " ")
			sl.Sudoers.Rule = append(sl.Sudoers.Rule, sudoersCombined)
		}
	}

	for _, sudoersdata := range sudoersData.Sudoers {
		sl.Sudoer[RuleType]
	}
*/
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




