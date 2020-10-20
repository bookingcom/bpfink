package genericdiff

import (
	"bufio"
	"os"

	"github.com/rs/zerolog"
)

//Diff struct that represents permission in the suoders file
type Diff struct {
	Rule string
}

//Parser struct to handle parsing of generic file with diff
type Parser struct {
	zerolog.Logger
	FileName    string
	GenericDiff []Diff
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
		p.GenericDiff = append(p.GenericDiff, Diff{
			Rule: " ",
		})
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || string(line[0]) == "#" {
			continue
		}
		p.GenericDiff = append(p.GenericDiff, Diff{
			Rule: line,
		})
	}
	return nil
}
