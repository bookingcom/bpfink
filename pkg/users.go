package pkg

import (
	"bufio"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"

	"github.com/bookingcom/bpfink/pkg/lang/passwd"
	"github.com/bookingcom/bpfink/pkg/lang/shadow"
)

type (
	//User struct representing a user
	User struct {
		Name     string
		Password string
		Keys     []string
	}

	//Users map of user objects
	Users map[string]*User

	//UsersListener struct of listener for users
	UsersListener struct {
		afero.Fs
		Shadow, Passwd string
		zerolog.Logger
	}

	passwdListener struct {
		zerolog.Logger
		users map[string]string
	}

	shadowListener struct {
		zerolog.Logger
		users map[string]string
	}
)

//Equal method to compare to users
func (u1 *User) Equal(u2 *User) bool {
	return u1.Name == u2.Name && u1.Password == u2.Password && ArrayEqual(u1.Keys, u2.Keys)
}

func userDiff(old, new Users) (add, del Users) {
	add, del = Users{}, Users{}
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

//NewUsersListener new function to create user listener
func NewUsersListener(options ...func(*UsersListener)) *UsersListener {
	sl := &UsersListener{Logger: zerolog.Nop()}
	for _, option := range options {
		option(sl)
	}
	return sl
}

func (sl *shadowListener) shadowParse(fileName string) error {
	shadowData := shadow.Parser{FileName: fileName, Logger: sl.Logger}
	err := shadowData.Parse()
	if err != nil {
		return err
	}
	sl.Debug().Msg("parsing shadow file")
	for _, user := range shadowData.Users {
		switch password := user.Password; password {
		case "!!", "*", "!", "":
		default:
			sl.users[user.Username] = MaskLeft(password)
		}
	}
	return nil
}

func (pl *passwdListener) passwdParse(fileName string) error {
	passwdData := passwd.Parser{FileName: fileName, Logger: pl.Logger}
	err := passwdData.Parse()
	if err != nil {
		return err
	}
	pl.Debug().Msg("parsing password file")
	for _, user := range passwdData.Users {
		if user.Shell == "/sbin/nologin" { // do not treat user with no shell
			continue
		}
		pl.users[user.Username] = user.Home
	}
	return nil
}

func (ul *UsersListener) file(name string) *File {
	return NewFile(func(file *File) {
		file.Logger, file.Fs, file.Path = ul.Logger, ul.Fs, name
	})
}

func (ul *UsersListener) shadow() (map[string]string, error) {
	users := map[string]string{}
	listener := &shadowListener{Logger: ul.Logger, users: users}
	err := listener.shadowParse(ul.Shadow)
	return listener.users, err
}

func (ul *UsersListener) passwd() (map[string]string, error) {
	users := map[string]string{}
	listener := &passwdListener{Logger: ul.Logger, users: users}
	err := listener.passwdParse(ul.Passwd)
	return listener.users, err
}

func (ul *UsersListener) parse() (Users, []string, error) {
	users, includes := Users{}, []string{ul.Passwd, ul.Passwd}
	passwds, err := ul.passwd()
	ul.Debug().Msgf("passwds: %v", passwds)
	if err != nil {
		return nil, nil, err
	}
	shadows, err := ul.shadow()
	ul.Debug().Msgf("shadows: %v", shadows)
	if err != nil {
		return nil, nil, err
	}

	for user, home := range passwds {
		authorized := path.Join(home, ".ssh", "authorized_keys")
		includes = append(includes, authorized)
		keys := keys(ul.file(authorized))
		if password, ok := shadows[user]; ok || len(keys) != 0 {
			users[user] = &User{user, password, keys}
		}
	}
	return users, includes, nil
}

func keys(authorized *File) (keys []string) {
	authorized.Debug().Str("file", authorized.Path).
		Msg("parsing authorized_keys")
	if fileExists(authorized.Path) {
		file, err := authorized.Open(authorized.Path)
		if err != nil {
			authorized.Error().Err(err).Str("file", authorized.Path).
				Msg("failed to open authorized keys file")
			return
		}
		defer func() {
			if err = file.Close(); err != nil {
				authorized.Error().Err(err)
			}
		}()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			key := "ssh-rsa "
			keyOffset := len(key)
			if i := strings.Index(line, key); i != -1 {
				keys = append(keys, line[i+keyOffset:])
			}
		}
		authorized.Debug().Str("file", authorized.Path).
			Strs("keys", keys).Msg("parsed authorized_keys")
		return
	}
	return
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) || info == nil {
		return false
	}
	return !info.IsDir()
}

//Register method takes in list of files to monitor for writes
func (ul *UsersListener) Register(includes []string) (out []string) {
	if base, ok := ul.Fs.(*afero.BasePathFs); ok {
		for _, file := range includes {
			rpath, _ := base.RealPath(file)
			out = append(out, rpath)
		}
		rpasswd, _ := base.RealPath(ul.Passwd)
		rshadow, _ := base.RealPath(ul.Shadow)
		out = append(out, rpasswd, rshadow)
	} else {
		out = append(out, ul.Passwd, ul.Shadow)
	}
	return ArrayClean(out)
}
