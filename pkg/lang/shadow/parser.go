package shadow

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	username = iota
	password
	last
	minimum
	maximum
	warning
	inactivity
	expiration
	reserved
)

// User struct that represents a user in shadow file
type User struct {
	Username   string
	Password   string
	Last       string
	Minimum    string
	Maximum    string
	Warning    string
	Inactivity string
	Expiration string
	Reserved   string
}

// Parser struct to handle parsing of shadow file
type Parser struct {
	zerolog.Logger
	FileName string
	Users    []User
}

// Parse func that parses a shadow file to collect users
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
			Username:   strings.TrimSpace(entries[username]),
			Password:   strings.TrimSpace(entries[password]),
			Last:       strings.TrimSpace(entries[last]),
			Minimum:    strings.TrimSpace(entries[minimum]),
			Maximum:    strings.TrimSpace(entries[maximum]),
			Warning:    strings.TrimSpace(entries[warning]),
			Inactivity: strings.TrimSpace(entries[inactivity]),
			Expiration: strings.TrimSpace(entries[expiration]),
			Reserved:   strings.TrimSpace(entries[reserved]),
		})
	}
	return nil
}
