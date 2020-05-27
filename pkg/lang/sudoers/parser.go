package sudoers

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	ruleType = iota
	ruleKey
	ruleValue
)

//Sudoer struct that represents permission in the suoders file
type Sudoer struct {
	RuleType string
	RuleKey	string
	RuleValue string
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
		if len(line) <= 0 || string(line[0]) == "#" {
			continue
		}
		//entries := strings.Fields(line)
		//entries := strings.Split(line, "=")

		//Replace delimiters with space
		replacer := strings.NewReplacer("=", " ", ":", " ", "+", " ")
		replacedLine := replacer.Replace(line)
		entries := strings.Fields(replacedLine)

		p.Logger.Debug().Msgf(" Sudoers entries are %v", entries)

		ruleValue := ""
		ruleValue = strings.Join(entries[2:], "")

		p.Sudoers = append(p.Sudoers, Sudoer{
			RuleType: strings.TrimSpace(entries[ruleType]),
			RuleKey: strings.TrimSpace(entries[ruleKey]),
			RuleValue: ruleValue,
		})
		p.Logger.Debug().Msgf(" Sudoers entries are %v", p.Sudoers)

	}
	return nil
}