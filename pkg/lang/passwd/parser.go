package passwd

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	username = iota
	password
	uid
	gid
	comment
	home
	shell
)

// User struct that represents a user in passwd file
type User struct {
	Username string
	Password string
	UID      string
	GID      string
	Comment  string
	Home     string
	Shell    string
}

// Parser struct to handle parsing of passwd file
type Parser struct {
	zerolog.Logger
	FileName string
	Users    []User
}

// Parse func that parses a passwd file to collect users
func (p *Parser) Parse() error {
	file, err := os.Open(p.FileName)
	if err != nil {
		p.Error().Err(err)
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			p.Error().Err(err)
		}
	}()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		entries := strings.Split(line, ":")
		p.Users = append(p.Users, User{
			Username: strings.TrimSpace(entries[username]),
			Password: strings.TrimSpace(entries[password]),
			UID:      strings.TrimSpace(entries[uid]),
			GID:      strings.TrimSpace(entries[gid]),
			Comment:  strings.TrimSpace(entries[comment]),
			Home:     strings.TrimSpace(entries[home]),
			Shell:    strings.TrimSpace(entries[shell]),
		})
	}
	return nil
}
