package errorpage

import (
	"github.com/openshift/oauth-server/pkg/server/locales"
	"github.com/openshift/oauth-server/pkg/userregistry/identitymapper"
)

const (
	// error occurred attempting to claim a user
	errorCodeClaim = "mapping_claim_error"
	// error occurred looking up the user
	errorCodeLookup = "mapping_lookup_error"
	// general authentication error
	errorCodeAuthentication = "authentication_error"
	// general grant error
	errorCodeGrant = "grant_error"
)

// AuthenticationErrorCode returns an error code for the given authentication error.
// If the error is not recognized, a generic error code is returned.
func AuthenticationErrorCode(err error) string {
	switch {
	case identitymapper.IsClaimError(err):
		return errorCodeClaim
	case identitymapper.IsLookupError(err):
		return errorCodeLookup
	default:
		return errorCodeAuthentication
	}
}

// AuthenticationErrorMessage returns an error message for the given authentication error code.
// If the error code is not recognized, a generic error message is returned.
func AuthenticationErrorMessage(code string, locale locales.Localization) string {
	switch code {
	case errorCodeClaim:
		return locale["CouldNotCreateUser"]
	case errorCodeLookup:
		return locale["CouldNotFindUser"]
	default:
		return locale["AnAuthenticationErrorOccurred"]
	}
}

// GrantErrorCode returns an error code for the given grant error.
// If the error is not recognized, a generic error code is returned.
func GrantErrorCode(err error) string {
	return errorCodeGrant
}

// GrantErrorMessage returns an error message for the given grant error code.
// If the error is not recognized, a generic error message is returned.
func GrantErrorMessage(code string, locale locales.Localization) string {
	return locale["GrantErrorOccurred"]
}
