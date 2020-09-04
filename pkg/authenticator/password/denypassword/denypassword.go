package denypassword

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	openshiftauthenticator "github.com/openshift/oauth-server/pkg/authenticator"
)

// denyPasswordAuthenticator denies all password requests
type denyPasswordAuthenticator struct {
}

// New creates a new password authenticator that denies any login attempt
func New() openshiftauthenticator.PasswordAuthenticator {
	return &denyPasswordAuthenticator{}
}

// AuthenticatePassword denies any login attempt
func (a denyPasswordAuthenticator) AuthenticatePassword(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
	return nil, false, nil
}
