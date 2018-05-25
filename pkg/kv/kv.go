package kv

import "fmt"

// NotFoundError represents an error when a key is not found
type NotFoundError struct {
	msg string // description of error
}

func (e *NotFoundError) Error() string { return e.msg }

// NewNotFoundError creates a new NotFoundError
func NewNotFoundError(msg string, args ...interface{}) *NotFoundError {
	return &NotFoundError{
		msg: fmt.Sprintf(msg, args...),
	}
}

// Service defines a basic key-value store. Implementations of this interface
// may or may not guarantee consistency or security properties.
type Service interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
	Test(key string) error
}
