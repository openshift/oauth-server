package authenticator

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/openshift/oauth-server/pkg/api"
)

type Assertion interface {
	AuthenticateAssertion(assertionType, data string) (*authenticator.Response, bool, error)
}

type Client interface {
	AuthenticateClient(client api.Client) (*authenticator.Response, bool, error)
}

// PasswordAuthenticator in an authenticator that uses username/password to verify identities
type PasswordAuthenticator interface {
	AuthenticatePassword(ctx context.Context, user, password string) (*authenticator.Response, bool, error)
}
