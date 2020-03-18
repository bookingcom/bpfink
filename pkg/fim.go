package pkg

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/rs/zerolog"
	"golang.org/x/xerrors"
)

const (
	resultTableName = "events"
	rulesTableName  = "rules"
	taskComLen      = 16
	dnameInlineLen  = 32
	chanSize        = 10 // totally arbitrary for now
	bpfAny          = 0  // flag for map updates.
)

type (
	//Event struct the represents event that is sent to user space from BPF
	Event struct {
		Mode   int32
		PID    uint32
		UID    uint32
		Size   uint32
		Inode  uint64
		Device uint64
		Com    string
		Path   string
	}
	rawEvent struct {
		Mode   int32
		PID    uint32
		UID    uint32
		Size   uint32
		Inode  uint64
		Device uint64
		Com    [taskComLen]byte
		Name   [dnameInlineLen]byte
	}
	//FIM struct that represents BPF event system
	FIM struct {
		mapping    *sync.Map
		reverse    *sync.Map
		Module     *elf.Module
		RulesTable *elf.Map
		resultsMap *elf.PerfMap
		Events     chan Event
		Errors     chan error
		zerolog.Logger
		closeChannelLoops chan struct{}
	}
)

//NewKey takes a path to file and generates a bpf map key
func NewKey(name string) (uint64, error) {
	fstat := &syscall.Stat_t{}
	if err := syscall.Stat(name, fstat); err != nil {
		return 0, err
	}
	return fstat.Ino, nil
}

//Encode takes in data, and encodes it for use in BPF
func Encode(i interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, binary.LittleEndian, i)
	return buf.Bytes(), err
}

//InitFIM function to initialize and start BPF
func InitFIM(bccFile string, logger zerolog.Logger) (*FIM, error) {
	mod := elf.NewModule(bccFile)

	err := mod.Load(nil)
	if err != nil {
		logger.Error().Err(err).Msgf("Error loading '%s' ebpf", bccFile)
		return nil, err
	}
	rulesTable := mod.Map(rulesTableName)
	if rulesTable == nil {
		err = errors.New("failed to create new elf map")
		logger.Error().Err(err)
		return nil, err
	}

	logger.Debug().Msg("unpinning maps")
	if err := syscall.Close(rulesTable.Fd()); err != nil {
		logger.Error().Msgf("error closing perf event fd: %v", err)
	}
	logger.Debug().Msg("maps unpinned")

	mod = elf.NewModule(bccFile)

	err = mod.Load(nil)
	if err != nil {
		logger.Error().Err(err).Msgf("Error loading '%s' ebpf", bccFile)
		return nil, err
	}

	rulesTable = mod.Map(rulesTableName)
	if rulesTable == nil {
		err = errors.New("failed to create new elf map")
		logger.Error().Err(err)
		return nil, err
	}

	err = mod.EnableKprobes(128)
	if err != nil {
		logger.Error().Err(err).Msg("Error loading kprobes")
		return nil, err
	}

	fim := &FIM{
		mapping:           &sync.Map{},
		reverse:           &sync.Map{},
		Module:            mod,
		RulesTable:        rulesTable,
		Events:            make(chan Event, chanSize),
		Errors:            make(chan error, chanSize),
		Logger:            logger,
		closeChannelLoops: make(chan struct{}, 1),
	}

	return fim, fim.start()
}

//Stats method to print status of code
func (f *FIM) Stats() string {
	count := 0
	f.mapping.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	return fmt.Sprintf("Currently watching %d files", count)
}

//StopBPF method to clean up bpf after running
func (f *FIM) StopBPF() error {
	f.resultsMap.PollStop()
	close(f.closeChannelLoops)
	f.Debug().Msg("polling stopped")
	f.mapping.Range(func(key, value interface{}) bool {
		ukey, ok := key.(uint64)
		if !ok {
			f.Error().Msgf("error asserting type")
			return true
		}
		if err := f.Module.DeleteElement(f.RulesTable, unsafe.Pointer(&ukey)); err != nil {
			f.Error().Err(err).Msgf("error removing key: %v, with error %s", ukey, err)
		}
		f.Debug().Msgf("Key removed: %v", ukey)
		return true
	})
	f.Debug().Msg("closing modules")
	err := f.Module.Close()

	if err != nil {
		f.Error().Err(err).Msgf("Error closing module: %v", err)
		return err
	}

	return nil
}

// error sends an error to the errors channel and drops the message if the channel is congested.
func (f *FIM) error(err error) {
	select {
	case f.Errors <- err:
	default:
	}
}

func (f *FIM) start() error {
	eventChannel := make(chan []byte, chanSize)
	missedChannel := make(chan uint64, chanSize)

	perfMap, err := elf.InitPerfMap(f.Module, resultTableName, eventChannel, missedChannel)
	if err != nil {
		return xerrors.Errorf("unable to init perf map: %w", err)
	}

	f.resultsMap = perfMap

	perfMap.PollStart()
	go func() {
		for {
			select {
			case missedCount, ok := <-missedChannel:
				if !ok {
					return
				}
				f.Debug().Msg("missed")
				f.error(xerrors.Errorf("log message count: %v", missedCount))
			case <-f.closeChannelLoops:
				f.Debug().Msg("chan Closed")
				return
			}

		}
	}()
	go func() {
		for {
			select {
			case data := <-eventChannel:
				f.Debug().Msg("event")
				e := rawEvent{}
				err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
				if err != nil {
					f.error(xerrors.Errorf("failed to decode received data %q: %w", data, err))
					continue
				}
				spath := ""
				f.Debug().Str("event", fmt.Sprint(e)).Msg("message from ebpf")
				cmdline := f.getCMDLine(e)
				comLen := 0
				if cmdline == "" {
					for index, bit := range e.Com {
						if bit == 0 {
							comLen = index
							break
						}
					}
					cmdline = string(e.Com[:comLen])
				}
				// When the user does something like mkdir -p multiple dir are create very quickly.
				// The BPF program is added the new dir inode into the look up map. So that events are not missed.
				// By introducing a very small sleep and retry logic, we allow for all bpf events to be received before
				// trying to process them. This accounts for the fact that events could be out of order.
				if e.Mode == 3 { //dir creation
					time.Sleep(50 * time.Millisecond)
					if _, ok := f.mapping.Load(e.Inode); !ok {
						time.Sleep(10 * time.Millisecond)
					}
				}

				if e.Mode == 4 || e.Mode == 3 {
					f.Debug().Msgf("name: %v", e.Name)
					f.Debug().Msgf("name: %v", string(e.Name[:len(e.Name)]))

					end := -1
					for index, char := range e.Name {
						if char == 0 && end == -1 {
							end = index
							break
						}
					}
					if end > 0 {
						spath = string(e.Name[:end])
						//todo build out fullpath/rel path.
					}
				} else {

					path, ok := f.mapping.Load(e.Inode)
					if !ok {
						f.Error().Msgf("could not find key: %v in map", e.Inode)
						var (
							pkey = (unsafe.Pointer(&e.Inode))
						)
						if err := f.Module.DeleteElement(f.RulesTable, pkey); err != nil {
							f.Error().Err(err)
						}
						continue
					}

					spath, ok = path.(string)
					if !ok {
						f.Error().Msgf("could not assert path into string key: %v in map", e.Inode)
					}
				}
				f.Events <- Event{
					e.Mode, e.PID, e.UID, e.Size, e.Inode, e.Device,
					cmdline,
					spath,
				}
			case <-f.closeChannelLoops:
				f.Debug().Msg("chan Closed")
				return
			}
		}
	}()
	return nil
}

func (f *FIM) getCMDLine(e rawEvent) string {
	path := fmt.Sprintf("/proc/%v/cmdline", e.PID)
	f.Debug().Msgf("cmdline path: %v", path)
	file, err := os.Open(path)
	if err != nil {
		f.Debug().Msg("file does not exist")
		return ""
	}
	defer func() {
		if err := file.Close(); err != nil {
			f.Error().Err(err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 {
			line = strings.ReplaceAll(line, "\u0000", " ")
			f.Debug().Msgf("cmdline text: %v", line)
			return line
		}
	}
	return ""
}

//AddFile method to add a new file to BPF monitor
func (f *FIM) AddFile(name string) error {
	key, err := NewKey(name)
	if err != nil {
		f.Error().Err(err).Msgf("Error stating file: %v", name)
		return err
	}
	f.Debug().Str("file", name).Msgf("created/updated Key : %v", key)
	value := 1
	pkey, pvalue := unsafe.Pointer(&key), unsafe.Pointer(&value)
	f.Debug().Str("file", name).Msg("pushing to ebpf")
	if err := f.Module.UpdateElement(f.RulesTable, pkey, pvalue, bpfAny); err != nil {
		return err
	}
	f.mapping.Store(key, name)
	f.reverse.Store(name, key)
	return nil
}

//RemoveFile method to remove a file from BPF monitor
func (f *FIM) RemoveFile(name string) error {
	rawKey, ok := f.reverse.Load(name)
	if !ok {
		err := errors.New("error getting key")
		f.Error().Err(err)
		return err
	}
	uintKey, ok := rawKey.(uint64)
	if !ok {
		err := errors.New("error casting key")
		f.Error().Err(err)
		return err
	}
	var (
		pkey = (unsafe.Pointer(&uintKey))
	)
	if err := f.Module.DeleteElement(f.RulesTable, pkey); err != nil {
		f.Error().Err(err)
		return err
	}

	id, ok := f.reverse.Load(name)
	if !ok {
		f.Error().Msgf("error loading ")
	}
	f.mapping.Delete(id)
	f.reverse.Delete(name)
	f.Debug().Msgf("map key: %v, with value: %v", id, name)
	return nil
}

//AddInode method to add a new file to BPF monitor
func (f *FIM) AddInode(key uint64, fileName string) error {

	f.Debug().Str("file", fileName).Msgf("created/updated Key : %v", key)
	value := 1
	pkey, pvalue := unsafe.Pointer(&key), unsafe.Pointer(&value)
	f.Debug().Str("file", fileName).Msg("pushing to ebpf")
	if err := f.Module.UpdateElement(f.RulesTable, pkey, pvalue, bpfAny); err != nil {
		return err
	}
	f.mapping.Store(key, fileName)
	f.reverse.Store(fileName, key)
	return nil
}

//RemoveInode method to remove a file from BPF monitor
func (f *FIM) RemoveInode(key uint64) (string, error) {
	rawName, ok := f.mapping.Load(key)
	if !ok {
		err := errors.New("error getting file name")
		f.Error().Err(err)
		return "", err
	}
	name, ok := rawName.(string)
	if !ok {
		err := errors.New("error casting file name")
		f.Error().Err(err)
		return "", err
	}
	var (
		pkey = (unsafe.Pointer(&key))
	)

	if err := f.Module.DeleteElement(f.RulesTable, pkey); err != nil {
		f.Error().Err(err)
		return "", err
	}

	f.mapping.Delete(key)
	f.reverse.Delete(name)
	f.Debug().Msgf("map key: %v, with value: %v", key, name)
	return name, nil
}

//GetFileFromInode look up filename for given inode
func (f *FIM) GetFileFromInode(key uint64) (string, error) {
	rawName, ok := f.mapping.Load(key)
	if !ok {
		err := errors.New("error getting file name")
		f.Error().Err(err)
		return "", err
	}
	name, ok := rawName.(string)
	if !ok {
		err := errors.New("error casting file name")
		f.Error().Err(err)
		return "", err
	}
	return name, nil
}
