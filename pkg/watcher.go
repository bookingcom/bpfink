package pkg

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

type (
	// Watcher struct defines a watcher object
	Watcher struct {
		zerolog.Logger
		*FIM
		Key           []byte
		Database      *AgentDB
		Consumers     []Consumer
		consumers     Consumers
		CloseChannels chan struct{}
	}
	// Register defines register interface for a watcher
	Register interface {
		Register() *sync.Map // map[string]Consumer
	}
	// Consumer interface describes a consumer for a watcher
	Consumer interface {
		Consume(e Event) error
		Register
	}
	// Consumers map of consumers
	Consumers struct {
		zerolog.Logger
		*sync.Map // map[string]Consumer
	}
)

var (
	// ErrReload var to define a reload of the consumer
	ErrReload = fmt.Errorf("reload consumer")
)

const (
	renameEvent = 2
	dirCreate   = 3
	fileCreate  = 4
	delFile     = -1
	delDir      = -2
)

// NewWatcher function to create new watcher function
func NewWatcher(options ...func(*Watcher)) *Watcher {
	watcher := &Watcher{Logger: zerolog.Nop(), consumers: Consumers{zerolog.Nop(), &sync.Map{}}, CloseChannels: make(chan struct{}, 1)}
	for _, option := range options {
		option(watcher)
	}
	return watcher
}

func (c Consumers) get(file string) (Consumer, error) {
	for {
		rawConsumer, ok := c.Load(file)
		if ok {
			consumer, ok := rawConsumer.(Consumer)
			if !ok {
				err := errors.New("failed to assert consumer from consumer map")
				c.Error().Err(err)
				return nil, err
			}
			return consumer, nil
		}
		if file == "/" || !strings.Contains(file, "/") {
			return nil, fmt.Errorf("no consumer found")
		}
		file = path.Dir(file)
	}
}

// Files method to get list of files
func (c Consumers) Files() (files []string) {
	c.Range(func(key, value interface{}) bool {
		stringKey, ok := key.(string)
		if !ok {
			c.Error().Msg("Failed to assert string for keys on consumer")
			return false
		}
		files = append(files, stringKey)
		return true
	})
	return
}

func (w *Watcher) add(file string, consumer Consumer) {
	switch err := w.AddFile(file); {
	case err == nil:
		w.consumers.Store(file, consumer)
		w.Debug().Str("file", file).Msgf("start watching")
	case IsNotExist(err):
		w.Debug().Str("file", file).
			Msgf("file does not exist polling filesystem")
		w.consumers.Store(file, NewFileMissing(w.Events, func(fm *FileMissing) {
			fm.Logger, fm.File, fm.Consumer = w.Logger, file, consumer
		}))
	default:
		w.Error().Str("file", file).AnErr("error", err).
			Msg("failed to add to watch list")
	}
}

func (w *Watcher) remove(file string) {
	if err := w.RemoveFile(file); err != nil {
		w.Error().Err(err).Str("file", file).Msg("failed to remove consumer")
		w.consumers.Delete(file)
	}
}

func (w *Watcher) addInode(event *Event, isdir bool) {
	file, err := w.GetFileFromInode(event.Inode)
	if err != nil {
		w.Debug().Msg("error getting file from inode")
		return
	}
	w.Debug().Msgf("File: %v found for inode", file)
	fullPath := fmt.Sprintf("%v/%v", file, event.Path)
	event.Path = fullPath

	state := &GenericState{
		GenericListener: NewGenericListener(func(l *GenericListener) {
			l.File = event.Path
			l.IsDir = isdir
			l.Logger = w.Logger
			l.Key = w.Key
		}),
	}
	consumer := &BaseConsumer{AgentDB: w.Database, ParserLoader: state}

	w.Consumers = append(w.Consumers, consumer)
	// consumer.Init()
	w.Debug().Msgf("fullPath: %v", event.Path)
	switch err := w.AddInode(event.Device, event.Path); {
	case err == nil:
		w.consumers.Store(event.Path, consumer)
		w.Debug().Str("file", event.Path).Msgf("start watching")
	case IsNotExist(err):
		w.Debug().Str("file", event.Path).
			Msgf("file does not exist polling filesystem")
		w.consumers.Store(event.Path, NewFileMissing(w.Events, func(fm *FileMissing) {
			fm.Logger, fm.File, fm.Consumer = w.Logger, event.Path, consumer
		}))
	default:
		w.Error().Str("file", event.Path).AnErr("error", err).
			Msg("failed to add to watch list")
	}
}

func (w *Watcher) removeInode(key uint64) {
	file, err := w.RemoveInode(key)
	if err != nil {
		w.Error().Err(err).Str("file", file).Msg("failed to remove consumer")
	}
	consumer, ok := w.consumers.Load(file)
	if !ok {
		return
	}
	for index, listConsumer := range w.Consumers {
		if listConsumer == consumer {
			w.Consumers = append(w.Consumers[:index], w.Consumers[index+1:]...) // remove item from slice
		}
	}
	w.consumers.Delete(file)
}

// Start method to start the watcher for the given consumers
func (w *Watcher) Start() error {
	defer func() {
		if i := recover(); i != nil {
			w.Fatal().Msgf("Panic Caught")
			w.Fatal().Msgf("Caught panic: %v", i)
			if err := w.Start(); err != nil {
				w.Error().Err(err)
			}
		}
	}()
	w.Debug().Msgf("consumer Count: %v", len(w.Consumers))
	for _, consumer := range w.Consumers {
		consumer.Register().Range(func(key, value interface{}) bool {
			stringFile, ok := key.(string)
			if !ok {
				w.Error().Msg("error casting file string from register")
				return false
			}
			w.Debug().Msgf("Adding File: %v", stringFile)
			consumerValue, ok := value.(Consumer)
			if !ok {
				w.Error().Msg("error casting consumer from register")
				return false
			}
			w.add(stringFile, consumerValue)
			return true
		})
	}
	for {
		select {
		case event := <-w.Events:
			switch event.Mode {
			case dirCreate:
				w.addInode(&event, true)
			case fileCreate:
				file, err := w.GetFileFromInode(event.Device) // event triggers occasionally after file has been created.
				if file == "" && err != nil {
					w.addInode(&event, false)
					event.Inode = event.Device // update so that event is processed correctly.
				} else {
					continue
				}
			}
			w.Debug().Object("event", LogEvent(event)).Msg("event caught")
			consumer, err := w.consumers.get(event.Path)
			if err != nil {
				if consumer == nil {
					w.Error().Msg("Consumer not found")
					break
				}
				consumer.Register().Range(func(key, value interface{}) bool {
					stringFile, ok := key.(string)
					if !ok {
						w.Error().Msg("error casting file string from register")
						return false
					}
					consumerValue, ok := value.(Consumer)
					if !ok {
						w.Error().Msg("error casting consumer from register")
						return false
					}
					w.add(stringFile, consumerValue)
					return true
				})
				consumer, err = w.consumers.get(event.Path)
				if err != nil {
					w.Error().Str("file", event.Path).Msg("failed to find consumer")
					continue
				}
			}
			go func(consumer Consumer, event Event) {
				switch err := consumer.Consume(event); err {
				case nil: // do nothing on nil
				case ErrReload:
					w.Debug().Msg("Reload triggered")
					consumer.Register().Range(func(key, value interface{}) bool {
						stringFile, ok := key.(string)
						if !ok {
							w.Error().Msg("error casting file string from register")
							return false
						}
						consumerValue, ok := value.(Consumer)
						if !ok {
							w.Error().Msg("error casting consumer from register")
							return false
						}
						w.Debug().Msg("Reloading consumers")
						w.remove(stringFile)
						w.add(stringFile, consumerValue)
						return true
					})
				default:
					w.Error().AnErr("error", err).Str("file", event.Path).Msg("consumer failed")
				}

				if err != ErrReload && event.Mode == renameEvent { // Rename event, reload consumer file, without consumer needed to worry about event types
					err = w.RemoveFile(event.Path)
					if err != nil {
						w.Error().Err(err)
					}
					w.add(event.Path, consumer)
				}

				switch event.Mode {
				case delFile:
					w.removeInode(event.Inode)
				case delDir:
					w.removeInode(event.Inode)
				}
			}(consumer, event)
		case <-w.CloseChannels:
			w.Debug().Msg("stopping watch")
			return nil
		}
	}
}

// Stop method to clean up anc gracefully exit the watcher and BPF
func (w *Watcher) Stop() error {
	close(w.CloseChannels)
	w.Logger.Debug().Msg("gracefully exiting BPF")
	return w.StopBPF()
}
