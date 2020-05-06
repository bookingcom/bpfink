package access

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	access = iota
	name
	tty
)

// Object struct representing a access config line
type Object struct {
	Access string
	Name   string
	TTY    string
}

// Parser struct to handle parsing access.conf
type Parser struct {
	zerolog.Logger
	FileName string
	Accesses []Object
}

// Parse func that parses a access file to collect accessObjects
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
		if len(line) == 0 || string(line[0]) == "#" {
			continue
		}

		entries := strings.Split(line, ":")
		p.Debug().Msgf("entries: %v", entries)
		ttyData := ""
		if len(entries) > 2 {
			ttyData = entries[tty]
			if len(entries) > 3 {
				ttyData = strings.Join(entries[2:], ":")
				commentIndex := strings.Index(ttyData, "#")
				if commentIndex >= 0 {
					ttyData = ttyData[:commentIndex]
				}
				ttyData = strings.TrimSpace(ttyData)
			}
		}
		p.Accesses = append(p.Accesses, Object{
			Access: strings.TrimSpace(entries[access]),
			Name:   strings.TrimSpace(entries[name]),
			TTY:    ttyData,
		})
	}
	return nil
}

// ADD func return if accessObject is type add
func (a *Object) ADD() bool {
	return a.Access == "+"
}

// DEL func return if accessObject is type deny
func (a *Object) DEL() bool {
	return a.Access == "-"
}
