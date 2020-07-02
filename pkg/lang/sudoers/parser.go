package sudoers

import (
	"bufio"
	"os"

	"github.com/rs/zerolog"
)

//Sudoer struct that represents permission in the suoders file
type Sudoer struct {
	Rule string
}

//Parser struct to handle parsing of sudoers file
type Parser struct {
	zerolog.Logger
	FileName string
	Sudoers  []Sudoer
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
	// If the file is empty
	stat, err := file.Stat()
	if err != nil {
		return err
	}

	if stat.Size() == 0 {
		p.Sudoers = append(p.Sudoers, Sudoer{
			Rule: " ",
		})
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || string(line[0]) == "#" {
			continue
		}
		p.Logger.Debug().Msgf("Sudoers entries are %v", line)
		p.Sudoers = append(p.Sudoers, Sudoer{
			Rule: line,
		})
	}
	return nil
}
