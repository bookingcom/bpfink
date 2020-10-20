package pkg

import (
	"bytes"
	"encoding/gob"
	"os"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"
)

type (
	// Set type to define Set
	Set map[string]struct{}
	// Map type to define Map
	Map map[string]string
	// File struct to define file
	File struct {
		afero.Fs
		zerolog.Logger
		Path string
	}
)

// Push method to push entries into set
func (s Set) Push(entries ...string) {
	for _, entry := range entries {
		s[entry] = struct{}{}
	}
}

// ToArray method to return items into slice of string
func (s Set) ToArray() (array []string) {
	for elt := range s {
		array = append(array, elt)
	}
	return
}

// Equal method to check if set1 == set2 deep compare
func (s Set) Equal(s2 Set) bool {
	if len(s) != len(s2) {
		return false
	}
	for k := range s {
		if _, ok := s2[k]; !ok {
			return false
		}
	}
	return true
}

// Array2Set function to convert Array to a set
func Array2Set(array []string) Set {
	set := Set{}
	set.Push(array...)
	return set
}

// ArrayDiff function to compare two arrays
func ArrayDiff(array1, array2 []string) (add, del []string) {
	set1, set2 := Array2Set(array1), Array2Set(array2)
	for elt := range set1 {
		if _, ok := set2[elt]; ok {
			delete(set1, elt)
			delete(set2, elt)
		}
	}
	return set2.ToArray(), set1.ToArray()
}

// ArrayClean function to clean an array of duplicates?
func ArrayClean(array []string) []string { return Array2Set(array).ToArray() }

// ArrayEqual checks if one array equals the second array
func ArrayEqual(array1, array2 []string) bool { return Array2Set(array1).Equal(Array2Set(array2)) }

// SetDiff check difference between two sets
// TODO: unused in current code
func SetDiff(old, new Set) (add, del Set) {
	add, del = Set{}, Set{}
	for k := range new {
		add.Push(k)
	}
	for k := range old {
		del.Push(k)
	}
	for k := range add {
		if _, ok := del[k]; ok {
			delete(add, k)
			delete(del, k)
		}
	}
	return
}

// Equal method to check if map1 == map2
func (m1 Map) Equal(m2 Map) bool {
	if len(m1) != len(m2) {
		return false
	}

	for k, v := range m1 {
		if w, ok := m2[k]; !ok || v != w {
			return false
		}
	}

	return true
}

// GobMarshal function to marshal interface to byte slice
func GobMarshal(i interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(i)
	return buf.Bytes(), err
}

// GobUnmarshal function to unmarshal gob
func GobUnmarshal(i interface{}, b []byte) error {
	buf := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buf)
	return decoder.Decode(i)
}

// IsNotExist Golang has a weird behavior regarding stat function if one entry in the path is a file
// We need to rewrite the os.IsNotExist function
func IsNotExist(err error) bool {
	if e, ok := err.(*os.PathError); ok {
		err = e.Err
	}
	return err == syscall.ENOENT || err == syscall.ENOTDIR ||
		err == os.ErrNotExist
}

// MaskLeft function to maskleft given string
func MaskLeft(s string) string {
	rs := []rune(s)
	for i := 0; i < len(rs)-4; i++ {
		rs[i] = 'X'
	}
	return string(rs)
}

// NewFile function to create new files
func NewFile(options ...func(*File)) *File {
	file := &File{Fs: afero.NewOsFs(), Logger: zerolog.Nop()}
	for _, option := range options {
		option(file)
	}
	file.Logger = file.With().Str("file", file.Path).Logger()
	return file
}
