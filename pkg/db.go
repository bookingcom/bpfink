package pkg

import (
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

type (
	//AgentDB struct containing db connection
	AgentDB struct {
		zerolog.Logger
		*bolt.DB
	}
)

const (
	bpfinkDB   = "bpfink"
	usersKey   = "users"
	accessKey  = "access"
	genericKey = "generic"
)

func (a *AgentDB) save(k string, v interface{}) error {
	return a.Update(func(tx *bolt.Tx) error {
		a.Logger.Debug().Msgf("saving %s", k)
		a.Logger.Debug().Msgf("saving: %#v", v)
		bucket, err := tx.CreateBucketIfNotExists([]byte(bpfinkDB))
		if err != nil {
			return err
		}
		bytes, err := GobMarshal(v)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(k), bytes)
	})
}

func (a *AgentDB) load(k string, v interface{}) error {
	return a.View(func(tx *bolt.Tx) error {
		a.Logger.Debug().Msgf("loading %s", k)
		defer a.Logger.Debug().Msgf("loading: %#v", v)
		bucket := tx.Bucket([]byte(bpfinkDB))
		if bucket == nil {
			return nil
		}
		bytes := bucket.Get([]byte(k))
		if bytes == nil {
			return nil
		}
		return GobUnmarshal(v, bytes)
	})
}

//SaveSudoers method to save a sudoer

//SaveUsers method to save Users
func (a *AgentDB) SaveUsers(users Users) error { return a.save(usersKey, users) }

//SaveAccess method to save access config
func (a *AgentDB) SaveAccess(access Access) error { return a.save(accessKey, access) }

//SaveGeneric method to save generic files
func (a *AgentDB) SaveGeneric(generic Generic) error { return a.save(genericKey, generic) }

//LoadUsers method to load users
func (a *AgentDB) LoadUsers() (Users, error) {
	users := Users{}
	return users, a.load(usersKey, &users)
}

//LoadAccess method to load access
func (a *AgentDB) LoadAccess() (Access, error) {
	access := Access{}
	return access, a.load(accessKey, &access)
}

//LoadGeneric method to load access
func (a *AgentDB) LoadGeneric() (Generic, error) {
	generic := Generic{}
	return generic, a.load(genericKey, &generic)
}
