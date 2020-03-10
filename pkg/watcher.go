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
	//Watcher struct defines a watcher object
	Watcher struct {
		zerolog.Logger
		*FIM
		Consumers     []Consumer
		consumers     Consumers
		CloseChannels chan struct{}
	}
	//Register defines register interface for a watcher
	Register interface {
		Register() *sync.Map //map[string]Consumer
	}
	//Consumer interface describes a consumer for a watcher
	Consumer interface {
		Consume(e Event) error
		Register
	}
	//Consumers map of consumers
	Consumers struct {
		zerolog.Logger
		*sync.Map //map[string]Consumer
	}
)

var (
	//ErrReload var to define a reload of the consumer
	ErrReload = fmt.Errorf("reload consumer")
)

//NewWatcher function to create new watcher function
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
				err := errors.New("Failed to assert consumer from consumer map")
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

//Files method to get list of files
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
	switch err := w.Add(file); {
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
	if err := w.Remove(file); err != nil {
		w.Error().Err(err).Str("file", file).Msg("failed to remove consumer")
		w.consumers.Delete(file)
	}
}

//Start method to start the watcher for the given consumers
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
			w.Debug().Object("event", LogEvent(event)).Msg("event caught")
			consumer, err := w.consumers.get(event.Path)
			if err != nil {
				if consumer == nil {
					w.Error().Msg("Nil sync Map")
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

				if err != ErrReload && event.Mode == 2 { //Rename event, reload consumer file, without consumer needed to worry about event types
					err = w.Remove(event.Path)
					if err != nil {
						w.Error().Err(err)
					}
					w.add(event.Path, consumer)
				}
			}(consumer, event)
		case <-w.CloseChannels:
			w.Debug().Msg("stopping watch")
			return nil
		}
	}
}

//Stop method to clean up anc gracefully exit the watcher and BPF
func (w *Watcher) Stop() error {
	close(w.CloseChannels)
	w.Logger.Debug().Msg("gracefully exiting BPF")
	return w.StopBPF()
}
