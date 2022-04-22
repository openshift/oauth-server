package github

import (
	"fmt"
	"strings"
)

type authorizationError struct {
	msg      string
	username string

	wrapped error
}

// NewAuthorizationErrorf creates an authorizationError that behaves like a
// typical error and offers in addition the username that experienced the
// authorization error.
func NewAuthorizationErrorf(username, format string, args ...interface{}) error {
	return &authorizationError{
		// TODO@ibihim: resuse username in err msg and then reduce username as arg in use.
		msg:      fmt.Sprintf(format, args...),
		username: username,
	}
}

// NewAuthorizationError creates an authorizationError that behaves like a
// typical error, wraps the previous error and offers in addition the username
// that experienced the authorization error.
func NewAuthorizationError(username string, msg string, err error) error {
	return &authorizationError{
		username: username,
		msg:      msg,
		wrapped:  err,
	}
}

// Username returns the Username that ran into the error.
func (err *authorizationError) Username() string {
	return err.username
}

// Error returns an error message.
func (err *authorizationError) Error() string {
	var builder strings.Builder

	if err.username != "" {
		builder.WriteString("user ")
		builder.WriteString(err.username)
		builder.WriteString(" ")
	}

	builder.WriteString(err.msg)

	if err.wrapped != nil {
		builder.WriteString(": ")
		builder.WriteString(err.wrapped.Error())
	}

	return builder.String()
}

// Unwrap support Golang's unwrap logic.
func (err *authorizationError) Unwrap() error {
	return err.wrapped
}
