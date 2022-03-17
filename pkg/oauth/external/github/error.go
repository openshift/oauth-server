package github

import "fmt"

type authorizationError string

func newAuthorizationErrorf(format string, args ...interface{}) authorizationError {
	return authorizationError(fmt.Sprintf(format, args...))
}

func (err authorizationError) AuthorizationDenialReason() string {
	return string(err)
}

func (err authorizationError) Error() string {
	return string(err)
}
