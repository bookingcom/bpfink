package pkg

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type (
	// State describes the interface for maintaining state of instances for a consumer
	State interface {
		Changed() bool
		Created() bool
		Notify(string, string)
		Teardown() error
	}
	// ParserLoader describes the interface for maintaining the data in a consumer
	ParserLoader interface {
		Load(db *AgentDB) error
		Save(db *AgentDB) error
		Parse() (State, error)
		Register() []string
	}
	// BaseConsumers is a type to describe multiple BaseConsumers
	BaseConsumers []*BaseConsumer

	// BaseConsumer is a struct that contains the base objects needed to make a consumer
	BaseConsumer struct {
		*AgentDB
		ParserLoader
		sync.RWMutex
	}
)

// Init function for populating a base consumer
func (bc *BaseConsumer) Init() error {
	if err := bc.Load(bc.AgentDB); err != nil {
		return err
	}
	state, err := bc.Parse()
	if err != nil {
		return err
	}
	if err := bc.Save(bc.AgentDB); err != nil {
		return err
	}
	if err := state.Teardown(); err == nil || err == ErrReload {
		return nil
	}
	return err
}

// Consume consumes an event
func (bc *BaseConsumer) Consume(e Event) error {
	bc.Lock()
	defer bc.Unlock()
	state, err := bc.Parse()
	if err != nil {
		return err
	}
	if !state.Changed() {
		return state.Teardown()
	}

	userID := fmt.Sprintf("%d", e.UID)
	if user, err := user.LookupId(userID); err != nil {
		bc.Err(err).Msgf("can't find user by UID %d", e.UID)
		state.Notify(e.Com, userID)
	} else {
		state.Notify(e.Com, user.Username)
	}

	if err := bc.Save(bc.AgentDB); err != nil {
		return err
	}
	return state.Teardown()
}

// Register method maps files to consumers.
func (bc *BaseConsumer) Register() *sync.Map {
	consumers := &sync.Map{}
	for _, file := range bc.ParserLoader.Register() {
		consumers.Store(file, bc)
	}
	return consumers
}

// Consumers returns a slice of consumers.
func (bc BaseConsumers) Consumers() (consumers []Consumer) {
	for _, consumer := range bc {
		consumers = append(consumers, consumer)
	}
	return consumers
}

/* --------------------------------- USERS --------------------------------- */

type (
	usersState struct {
		users    Users
		includes []string
	}
	// UsersState struct keeps track of state changes based on UserListener struct and methods
	UsersState struct {
		*UsersListener
		current, next *usersState
	}
)

// Parse calls parse(), and update new UserState
func (us *UsersState) Parse() (State, error) {
	users, includes, err := us.parse()
	if err != nil {
		return nil, err
	}
	us.next = &usersState{includes: includes, users: users}
	return us, nil
}

// Changed checks if the new UserState instance is different from old UserState instance
func (us *UsersState) Changed() bool {
	add, del := userDiff(us.current.users, us.next.users)
	return len(add) != 0 || len(del) != 0
}

// Created checks if the current UserState has been created
func (us *UsersState) Created() bool { return len(us.current.users) == 0 }

// Notify is the method to notify of a change in state
func (us *UsersState) Notify(cmd string, user string) {
	add, del := userDiff(us.current.users, us.next.users)
	us.Warn().
		Array("users", LogUsers(us.next.users)).
		Array("add", LogUsers(add)).
		Array("del", LogUsers(del)).
		Str("processName", cmd).
		Str("user", user).
		Msg("Users Modified")
}

func (us *UsersState) reload() error {
	if ArrayEqual(us.current.includes, us.next.includes) {
		return nil
	}
	us.Debug().
		Strs("old", us.current.includes).
		Strs("new", us.next.includes).
		Msg("includes changed")
	return ErrReload
}

// Teardown is the reset method when a change has been detected. Set new state to old state, and reload.
func (us *UsersState) Teardown() error {
	us.current = us.next
	return us.reload()
}

// Register returns a list of files to watch for changes
func (us *UsersState) Register() []string {
	return us.UsersListener.Register(us.current.includes)
}

// Save commits a state to the local DB instance.
func (us *UsersState) Save(db *AgentDB) error {
	us.Debug().Array("users", LogUsers(us.next.users)).Msg("save users")
	return db.SaveUsers(us.next.users)
}

// Load reads in current state from local db instance
func (us *UsersState) Load(db *AgentDB) error {
	users, err := db.LoadUsers()
	if err != nil {
		return err
	}
	us.current = &usersState{users: users}
	return err
}

/* --------------------------------- ACCESS --------------------------------- */

type (
	// AccessState struct keeps track of state changes based on AccessListener struct and methods
	AccessState struct {
		*AccessListener
		current, next Access
	}
)

// Parse calls parse(), and update new AccessState
func (as *AccessState) Parse() (State, error) {
	access, err := as.parse()
	if err != nil {
		return nil, err
	}
	as.next = access
	return as, nil
}

// Changed checks if the new AccessState instance is different from old AccessState instance
func (as *AccessState) Changed() bool {
	add, del := accessDiff(as.current, as.next)
	return !add.IsEmpty() || !del.IsEmpty()
}

// Created checks if the current AccessState has been created
func (as *AccessState) Created() bool { return as.current.IsEmpty() }

// Notify is the method to notify of a change in state
func (as *AccessState) Notify(cmd string, user string) {
	add, del := accessDiff(as.current, as.next)
	as.Warn().
		Object("access", LogAccess(as.next)).
		Object("add", LogAccess(add)).
		Object("del", LogAccess(del)).
		Str("processName", cmd).
		Str("user", user).
		Msg("access entries")
}

// Teardown is the reset method when a change has been detected. Set new state to old state, and reload.
func (as *AccessState) Teardown() error {
	as.current = as.next
	return nil
}

// Save commits a state to the local DB instance.
func (as *AccessState) Save(db *AgentDB) error {
	as.Debug().Object("access", LogAccess(as.next)).Msg("save access")
	return db.SaveAccess(as.next)
}

// Load reads in current state from local db instance
func (as *AccessState) Load(db *AgentDB) (err error) {
	as.current, err = db.LoadAccess()
	return
}

/* --------------------------------- Generic --------------------------------- */

type (
	// GenericState struct keeps track of state changes based on GenericListener struct and methods
	GenericState struct {
		*GenericListener
		current, next Generic
	}
)

// Parse calls parse(), and update new UserState
func (gs *GenericState) Parse() (State, error) {
	gs.Debug().Msg("parsing generic file")

	switch generic, err := gs.parse(); {
	case err == nil:
		gs.next = generic
		return gs, nil
	case IsNotExist(err): // file deleted
		return gs, nil
	default:
		return nil, err
	}
}

// Changed checks if the new UserState instance is different from old UserState instance
func (gs *GenericState) Changed() bool {
	if gs.next.IsEmpty() && !gs.current.IsEmpty() {
		return true
	}
	gs.Debug().Msgf("A: %v VS B: %v", gs.current.Contents, gs.next.Contents)
	res := bytes.Compare(gs.current.Contents, gs.next.Contents)
	return res != 0
}

// Created checks if the current UserState has been created
func (gs *GenericState) Created() bool { return len(gs.current.Contents) == 0 }

// Notify is the method to notify of a change in state
func (gs *GenericState) Notify(cmd string, user string) {
	if gs.current.IsEmpty() {
		gs.Warn().
			Object("generic", LogGeneric(*gs)).
			Str("file", gs.File).
			Str("processName", cmd).
			Str("user", user).
			Msg("generic file created")
		return
	}
	if gs.next.IsEmpty() {
		gs.Warn().
			Object("generic", LogGeneric(*gs)).
			Str("file", gs.File).
			Str("processName", cmd).
			Str("user", user).
			Msg("generic file deleted")
		return
	}
	gs.Warn().
		Object("generic", LogGeneric(*gs)).
		Str("file", gs.File).
		Str("processName", cmd).
		Str("user", user).
		Msg("generic file Modified")
}

// Teardown is the reset method when a change has been detected. Set new state to old state, and reload.
func (gs *GenericState) Teardown() error {
	gs.current = gs.next
	gs.next = Generic{}
	return nil
}

// Register returns a list of files to watch for changes
func (gs *GenericState) Register() []string {
	return gs.GenericListener.Register()
}

// Save commits a state to the local DB instance.
func (gs *GenericState) Save(db *AgentDB) error {
	gs.Debug().Object("generic", LogGeneric(*gs)).Msg("save generic file")
	return db.SaveGeneric(gs.next)
}

// Load reads in current state from local db instance
func (gs *GenericState) Load(db *AgentDB) error {
	generic, err := db.LoadGeneric()
	if err != nil {
		return err
	}
	gs.current = generic
	return err
}

/* --------------------------------- GENERIC FILE DIFF --------------------------------- */
type (
	//GenericDiffState struct keeps track of state changes based on GenericDiffListener struct and methods
	GenericDiffState struct {
		*GenericDiffListener
		current, next GenericDiff
	}
)

//Parse calls parse(), and update new GenericDiffState
func (gds *GenericDiffState) Parse() (State, error) {
	switch genericDiff, err := gds.parse(); {
	case err == nil:
		gds.next = genericDiff
		return gds, nil
	case IsNotExist(err): // file deleted
		return gds, nil
	default:
		return nil, err
	}
}

//Changed checks if the new GenericDiffState instance is different from old GenericDiffState instance
func (gds *GenericDiffState) Changed() bool {
	if gds.next.IsEmpty() && !gds.current.IsEmpty() {
		return true
	}
	add, del := findGenericDiff(gds.current, gds.next)
	return !add.IsEmpty() || !del.IsEmpty()
}

//Created checks if the current GenericDiffState has been created
func (gds *GenericDiffState) Created() bool { return gds.current.IsEmpty() }

//Notify is the method to notify of a change in state
func (gds *GenericDiffState) Notify(cmd string, user string) {
	add, del := findGenericDiff(gds.current, gds.next)
	if gds.current.IsEmpty() {
		gds.Warn().
			Object("add", LogGenericDiff(add)).
			Object("del", LogGenericDiff(del)).
			Str("file", gds.genericDiff).
			Str("processName", cmd).
			Str("user", user).
			Msg("Critical Generic file created")
		return
	}
	if gds.next.IsEmpty() {
		gds.Warn().
			Object("add", LogGenericDiff(add)).
			Object("del", LogGenericDiff(del)).
			Str("file", gds.genericDiff).
			Str("processName", cmd).
			Str("user", user).
			Msg("Critical Generic file deleted")
		return
	}
	gds.Warn().
		Object("add", LogGenericDiff(add)).
		Object("del", LogGenericDiff(del)).
		Str("file", gds.genericDiff).
		Str("processName", cmd).
		Str("user", user).
		Msg("Critical Generic file modified")
}

//Teardown is the reset method when a change has been detected. Set new state to old state, and reload.
func (gds *GenericDiffState) Teardown() error {
	gds.current = gds.next
	gds.next = GenericDiff{}
	return nil
}

//Register returns a list of files to watch for changes
func (gds *GenericDiffState) Register() []string {
	return gds.GenericDiffListener.Register()
}

//Save commits a state to the local DB instance.
func (gds *GenericDiffState) Save(db *AgentDB) error {
	gds.Debug().Object("generic diff", LogGenericDiff(gds.next)).Msg("Save critical generic file")
	return db.SaveGenericDiff(gds.next)
}

//Load reads in current state from local db instance
func (gds *GenericDiffState) Load(db *AgentDB) (err error) {
	genericDiff, err := db.LoadGenericDiff()
	if err != nil {
		return err
	}
	gds.current = genericDiff
	return err
}

/* ------------------------------ NOP CONSUMER ------------------------------ */
type nopConsumer struct{}

func (np nopConsumer) Register() *sync.Map { return nil }
func (np nopConsumer) Consume(Event) error { return nil }

/* ------------------------------ FILE MISSING ------------------------------ */

// FileMissing struct is used when a watched file cannot be located
type FileMissing struct {
	File string
	Consumer
	zerolog.Logger
}

const pollingDuration = 10 * time.Second

// NewFileMissing function watches for a file to be found, and adds the file to be monitored.
func NewFileMissing(events chan Event, options ...func(*FileMissing)) *FileMissing {
	// NopConsumer is a fake consumer
	var NopConsumer = nopConsumer{}

	fm := &FileMissing{File: "/dev/null", Consumer: NopConsumer, Logger: zerolog.Nop()}
	for _, option := range options {
		option(fm)
	}
	fm.Logger = fm.Logger.With().Str("file", fm.File).
		Str("consumer", "file missing").Logger()
	go fm.start(events)
	return fm
}

func (fm *FileMissing) start(events chan Event) {
	for range time.Tick(pollingDuration) { //nolint
		if _, err := os.Stat(fm.File); err == nil {
			fm.Debug().Msg("file found")
			events <- Event{Path: fm.File, Mode: 1}
			fm.Debug().Msg("pushed to event")
			return
		}
	}
}

// Register method registers the newly found file to the correct consumer
func (fm *FileMissing) Register() *sync.Map {
	out := &sync.Map{}
	out.Store(fm.File, fm)

	if _, err := os.Stat(fm.File); err == nil {
		out = fm.Consumer.Register()
	}
	return out
}
