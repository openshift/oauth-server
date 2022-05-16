package api

// AuthorizationDeniedError must be raised by external identity checkers to
// signal that even though authentication was successful, futher rules denied
// access.
//
// Calls to Error() will be passed directly to the wrapped error.
type AuthorizationDeniedError struct {
	identity UserIdentityInfo
	error
}

// NewAuthorizationDeniedError wraps the given error in an
// AuthorizationFailedError type, which exposes the given identity.
func NewAuthorizationDeniedError(identity UserIdentityInfo, err error) AuthorizationDeniedError {
	return AuthorizationDeniedError{
		identity: identity,
		error:    err,
	}
}

// Identity returns identity information relative to a denied access attempt.
func (e AuthorizationDeniedError) Identity() UserIdentityInfo { return e.identity }

// Unwrap returns the underlying error to satisfy errors.As() and errors.Is().
func (e AuthorizationDeniedError) Unwrap() error { return e.error }

// AuthorizationFailedError can be raised by external identity checkers to
// return information about identity, when a runtime error occurs while
// identity information is already available.
//
// Calls to Error() will be passed directly to the wrapped error.
type AuthorizationFailedError struct {
	identity UserIdentityInfo
	error
}

// NewAuthorizationFailedError wraps the given error in an
// AuthorizationFailedError type, which exposes the given identity.
func NewAuthorizationFailedError(identity UserIdentityInfo, err error) AuthorizationFailedError {
	return AuthorizationFailedError{
		identity: identity,
		error:    err,
	}
}

// Identity returns identity information relative to a failed access attempt.
func (e AuthorizationFailedError) Identity() UserIdentityInfo { return e.identity }

// Unwrap returns the underlying error to satisfy errors.As() and errors.Is().
func (e AuthorizationFailedError) Unwrap() error { return e.error }
