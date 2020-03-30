package sudoers

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	user = iota
	host
	accounts
	commands
)

//Sudoer struct that represents a line in the suoders file
type Sudoer struct {
	User string
	Host string
	Accounts string
	Commands string
}

//Parser struct to handle parsing of sudoers file
type Parser struct {
	zerolog.Logger
	FileName string
	Sudoers    []Sudoer
}

//Parse func that parses a passwd file to collect users
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
		if len(line) <= 0 || string(line[0]) == "#" || strings.HasPrefix(line, "Defaults") {
			continue
		}

		entries := strings.Fields(line)
		p.Logger.Debug().Msgf(" Sudoers entries are %v", entries)
		p.Sudoers = append(p.Sudoers, Sudoer{
			User: strings.TrimSpace(entries[user]),
			Host: strings.TrimSpace(entries[host]),
			Accounts: strings.TrimSpace(entries[accounts]),
			Commands: strings.TrimSpace(entries[commands]),
		})
	}
	return nil
}