package identitymapper

import (
	"context"
	"fmt"

	userapi "github.com/openshift/api/user/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	kerrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

var _ = UserForNewIdentityGetter(&StrategyClaim{})

// StrategyClaim associates a new identity with a user with the identity's preferred username
// if no other identities are already associated with the user
type StrategyClaim struct {
	user        userclient.UserInterface
	initializer Initializer
}

type claimError struct {
	User     *userapi.User
	Identity *userapi.Identity
}

func IsClaimError(err error) bool {
	_, ok := err.(claimError)
	return ok
}
func NewClaimError(user *userapi.User, identity *userapi.Identity) error {
	return claimError{User: user, Identity: identity}
}

func (c claimError) Error() string {
	return fmt.Sprintf("user %q cannot be claimed by identity %q because it is already mapped to %v", c.User.Name, c.Identity.Name, c.User.Identities)
}

func NewStrategyClaim(user userclient.UserInterface, initializer Initializer) UserForNewIdentityGetter {
	return &StrategyClaim{user, initializer}
}

func (s *StrategyClaim) UserForNewIdentity(ctx context.Context, preferredUserName string, identity *userapi.Identity) (*userapi.User, error) {

	persistedUser, err := s.user.Get(context.TODO(), preferredUserName, metav1.GetOptions{})

	switch {
	case kerrs.IsNotFound(err):
		// CreateUser a new user, propagating any "already exists" errors
		desiredUser := &userapi.User{}
		desiredUser.Name = preferredUserName
		desiredUser.Identities = []string{identity.Name}

		if err := s.initializer.InitializeUser(identity, desiredUser); err != nil {
			return nil, fmt.Errorf("initialize user with identity (%v): %w", identity, err)
		}

		return s.user.Create(context.TODO(), desiredUser, metav1.CreateOptions{})

	case err == nil:
		// If the existing user already references our identity, we're done
		if sets.NewString(persistedUser.Identities...).Has(identity.Name) {
			return persistedUser, nil
		}

		// If this user has no other identities, claim, initialize, and update
		if len(persistedUser.Identities) == 0 {
			persistedUser.Identities = []string{identity.Name}

			if err := s.initializer.InitializeUser(identity, persistedUser); err != nil {
				return nil, fmt.Errorf("initialize user with identity (%v): %w", identity, err)
			}

			return s.user.Update(context.TODO(), persistedUser, metav1.UpdateOptions{})
		}

		// Otherwise another identity has already claimed this user, return an error
		return nil, NewClaimError(persistedUser, identity)

	default:
		// Fail on errors other than "not found"
		return nil, err
	}

}
