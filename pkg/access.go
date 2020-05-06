package pkg

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"

	"github.com/bookingcom/bpfink/pkg/lang/access"
)

type (
	// Access struct used to store changes to access.conf
	Access struct {
		Grant, Deny []string
	}
	// AccessListener struct used for filestream events.
	AccessListener struct {
		zerolog.Logger
		afero.Fs
		access string
	}
	accessListener struct {
		Access
		zerolog.Logger
	}
)

func accessDiff(old, new Access) (add, del Access) {
	add, del = Access{}, Access{}
	add.Grant, del.Grant = ArrayDiff(old.Grant, new.Grant)
	add.Deny, del.Deny = ArrayDiff(old.Deny, new.Deny)
	return
}

// IsEmpty method to check if diff is empty
func (a Access) IsEmpty() bool { return len(a.Grant) == 0 && len(a.Deny) == 0 }

// AccessFileOpt function used to return metadata on a file
func AccessFileOpt(fs afero.Fs, path string, logger zerolog.Logger) func(*AccessListener) {
	return func(listener *AccessListener) {
		listener.Fs = NewFile(func(file *File) {
			file.Fs, file.Path, file.Logger = fs, path, logger
		})
		listener.access = path
		listener.Logger = logger
	}
}

// NewAccessListener function to create a new file event listener
func NewAccessListener(options ...func(*AccessListener)) *AccessListener {
	al := &AccessListener{Logger: zerolog.Nop()}
	for _, option := range options {
		option(al)
	}
	return al
}

func (al *AccessListener) parse() (Access, error) {
	listener := &accessListener{Logger: al.Logger}
	al.Debug().Msgf("parsing access: %v", al.access)

	err := listener.accessParse(al.access)
	if err != nil {
		return Access{}, err
	}
	return listener.Access, nil
}

func (al *accessListener) accessParse(fileName string) error {
	accessData := access.Parser{FileName: fileName, Logger: al.Logger}
	err := accessData.Parse()
	if err != nil {
		return err
	}
	for _, accessctx := range accessData.Accesses {
		name := accessctx.Name
		switch {
		case accessctx.ADD():
			al.Access.Grant = append(al.Access.Grant, name)
		case accessctx.DEL():
			al.Access.Deny = append(al.Access.Deny, name)
		default:
			al.Error().Err(fmt.Errorf("unexpected entry value for '%s'", name)).
				Msg("failed to parse")
		}
	}
	return nil
}

// Register method returns list of paths to files to be watched
func (al *AccessListener) Register() []string {
	if base, ok := al.Fs.(*afero.BasePathFs); ok {
		path, _ := base.RealPath(al.access)
		return []string{path}
	}
	return []string{al.access}
}
