package pkg

import (
	"github.com/rs/zerolog"
)

type (
	// ZerologMarshalerObjectFunc function signature for marshaling an object
	ZerologMarshalerObjectFunc func(e *zerolog.Event)
	// ZerologMarshalerArrayFunc function signature for marshaling an array
	ZerologMarshalerArrayFunc func(a *zerolog.Array)
	// LogEvent type wrapper
	LogEvent Event
	// LogUsers type wrapper
	LogUsers Users
	// LogUser type wrapper
	LogUser User
	// LogAccess type wrapper
	LogAccess Access
	// LogGeneric type wrapper
	LogGeneric GenericState
	//LogGenericDiff type wrapper
	LogGenericDiff GenericDiff
)

// MarshalZerologObject method to wrap a logger
func (zmof ZerologMarshalerObjectFunc) MarshalZerologObject(e *zerolog.Event) { zmof(e) }

// MarshalZerologArray method to wrap logger
func (zmaf ZerologMarshalerArrayFunc) MarshalZerologArray(a *zerolog.Array) { zmaf(a) }

// MarshalZerologObject method to marshal object
func (le LogEvent) MarshalZerologObject(e *zerolog.Event) {
	e.Str("path", le.Path)
	e.Int32("mode", le.Mode)
	e.Uint64("inode", le.Inode)
	e.Str("command", le.Com)
}

// MarshalZerologArray method to marshal array
func (lu LogUsers) MarshalZerologArray(a *zerolog.Array) {
	for _, user := range lu {
		a.Object(LogUser(*user))
	}
}

// MarshalZerologObject method to marshal user event
func (lu LogUser) MarshalZerologObject(e *zerolog.Event) {
	e.Str("user", lu.Name)
	e.Str("passwd", lu.Password)
	var truncKeys []string
	maxLength := 80
	for _, key := range lu.Keys {
		keyLen := len(key)
		if keyLen < maxLength {
			truncKeys = append(truncKeys, key)
		} else {
			truncKeys = append(truncKeys, key[keyLen-maxLength:])
		}
	}
	e.Strs("keys", truncKeys)
}

// MarshalZerologObject method to marshal access object
func (la LogAccess) MarshalZerologObject(e *zerolog.Event) {
	e.Strs("grant", la.Grant)
	e.Strs("deny", la.Deny)
}

// MarshalZerologObject method to marshal generic object
func (lg LogGeneric) MarshalZerologObject(e *zerolog.Event) {
	e.Hex("current", lg.current.Contents)
	e.Hex("next", lg.next.Contents) // update to aes-gcm
}

//MarshalZerologObject method to marshal generic diff object
func (lgd LogGenericDiff) MarshalZerologObject(e *zerolog.Event) {
	e.Strs("Content", lgd.Rule)
}
