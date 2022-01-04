package registrystorage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/RangelReale/osin"
	"gopkg.in/square/go-jose.v2/jwt"

	tokenreviewv1 "k8s.io/api/authentication/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/klog/v2"

	oauthapi "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	scopemetadata "github.com/openshift/library-go/pkg/authorization/scopemetadata"

	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/oauth-server/pkg/oauth/handlers"
	"github.com/openshift/oauth-server/pkg/scopecovers"
	"github.com/openshift/oauth-server/pkg/server/crypto"
)

type storage struct {
	accesstoken    oauthclient.OAuthAccessTokenInterface
	authorizetoken oauthclient.OAuthAuthorizeTokenInterface
	tokenReview    authenticationv1client.TokenReviewInterface
	client         api.OAuthClientGetter
	tokentimeout   int32
}

func New(
	access oauthclient.OAuthAccessTokenInterface,
	authorize oauthclient.OAuthAuthorizeTokenInterface,
	client api.OAuthClientGetter,
	tokenReview authenticationv1client.TokenReviewInterface,
	tokentimeout int32,
) osin.Storage {
	return &storage{
		accesstoken:    access,
		authorizetoken: authorize,
		client:         client,
		tokentimeout:   tokentimeout,
		tokenReview:    tokenReview,
	}
}

type clientWrapper struct {
	id          string
	client      *oauthapi.OAuthClient
	reviewToken func(ctx context.Context, token string, audiences []string) (*tokenreviewv1.TokenReview, error)
}

// Ensure we implement the secret matcher method that allows us to validate multiple secrets
var _ = osin.Client(&clientWrapper{})
var _ = osin.ClientSecretMatcher(&clientWrapper{})
var _ = handlers.TokenMaxAgeSeconds(&clientWrapper{})
var _ = handlers.TokenTimeoutSeconds(&clientWrapper{})

func (w *clientWrapper) GetId() string {
	return w.id
}

func (w *clientWrapper) GetSecret() string {
	// Required to implement osin.Client, but should never be called, since we implement osin.ClientSecretMatcher
	panic("unsupported")
}

func (w *clientWrapper) ClientSecretMatches(secret string) bool {
	if crypto.IsEqualConstantTime(w.client.Secret, secret) {
		return true
	}

	for _, additionalSecret := range w.client.AdditionalSecrets {
		if crypto.IsEqualConstantTime(additionalSecret, secret) {
			return true
		}
	}

	// assume this is an SA token
	tok, err := jwt.ParseSigned(secret)
	if err != nil {
		return false
	}

	if tok != nil {
		public := &jwt.Claims{}
		err := tok.UnsafeClaimsWithoutVerification(public)
		if err != nil {
			klog.V(4).Infof("failed to get unsafe claims: %v", err)
			return false
		}
		tokenAuds := authenticator.Audiences(public.Audience)
		tokenReview, err := w.reviewToken(context.TODO(), secret, tokenAuds)
		if err != nil {
			klog.V(4).Infof("the tokenreview failed: %v", err)
			return false
		}

		if tokenReview.Status.User.Username != w.client.Name {
			return false
		}
		return true
	}

	return false
}

func (w *clientWrapper) GetRedirectUri() string {
	if len(w.client.RedirectURIs) == 0 {
		return ""
	}
	return strings.Join(w.client.RedirectURIs, ",")
}

func (w *clientWrapper) GetUserData() interface{} {
	return w.client
}

func (w *clientWrapper) GetTokenMaxAgeSeconds() *int32 {
	return w.client.AccessTokenMaxAgeSeconds
}

func (w *clientWrapper) GetAccessTokenInactivityTimeoutSeconds() *int32 {
	return w.client.AccessTokenInactivityTimeoutSeconds
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *storage) Close() {
}

// GetClient loads the client by id (client_id)
func (s *storage) GetClient(id string) (osin.Client, error) {
	c, err := s.client.Get(context.TODO(), id, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &clientWrapper{id, c, newTokenReviewer(s.tokenReview)}, nil
}

func newTokenReviewer(tokenReviewer authenticationv1client.TokenReviewInterface) func(ctx context.Context, token string, audiences []string) (*tokenreviewv1.TokenReview, error) {
	return func(ctx context.Context, token string, audiences []string) (*tokenreviewv1.TokenReview, error) {
		return tokenReviewer.Create(ctx, &tokenreviewv1.TokenReview{Spec: tokenreviewv1.TokenReviewSpec{Token: token, Audiences: audiences}}, metav1.CreateOptions{})
	}
}

// SaveAuthorize saves authorize data.
func (s *storage) SaveAuthorize(data *osin.AuthorizeData) error {
	token, err := s.convertToAuthorizeToken(data)
	if err != nil {
		return err
	}
	_, err = s.authorizetoken.Create(context.TODO(), token, metav1.CreateOptions{})
	return err
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	authorize, err := s.authorizetoken.Get(context.TODO(), TokenToObjectName(code), metav1.GetOptions{})
	if kerrors.IsNotFound(err) {
		klog.V(5).Info("Authorization code not found")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.convertFromAuthorizeToken(code, authorize)
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *storage) RemoveAuthorize(code string) error {
	// TODO: return no error if registry returns IsNotFound
	return s.authorizetoken.Delete(context.TODO(), TokenToObjectName(code), metav1.DeleteOptions{})
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *storage) SaveAccess(data *osin.AccessData) error {
	token, err := s.convertToAccessToken(data)
	if err != nil {
		return err
	}
	_, err = s.accesstoken.Create(context.TODO(), token, metav1.CreateOptions{})
	return err
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *storage) LoadAccess(code string) (*osin.AccessData, error) {
	access, err := s.accesstoken.Get(context.TODO(), TokenToObjectName(code), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return s.convertFromAccessToken(code, access)
}

// RemoveAccess revokes or deletes an AccessData.
func (s *storage) RemoveAccess(code string) error {
	// TODO: return no error if registry returns IsNotFound
	return s.accesstoken.Delete(context.TODO(), TokenToObjectName(code), metav1.DeleteOptions{})
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *storage) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, errors.New("not implemented")
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *storage) RemoveRefresh(code string) error {
	return errors.New("not implemented")
}

func (s *storage) convertToAuthorizeToken(data *osin.AuthorizeData) (*oauthapi.OAuthAuthorizeToken, error) {
	token := &oauthapi.OAuthAuthorizeToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: TokenToObjectName(data.Code),
			// creation time is controlled by the API
			// CreationTimestamp: metav1.Time{Time: data.CreatedAt},
		},
		CodeChallenge:       data.CodeChallenge,
		CodeChallengeMethod: data.CodeChallengeMethod,
		ClientName:          data.Client.GetId(),
		ExpiresIn:           int64(data.ExpiresIn),
		Scopes:              scopecovers.Split(data.Scope),
		RedirectURI:         data.RedirectUri,
		State:               data.State,
	}
	var err error
	if token.UserName, token.UserUID, err = convertFromUser(data.UserData); err != nil {
		return nil, err
	}
	return token, nil
}

func (s *storage) convertFromAuthorizeToken(code string, authorize *oauthapi.OAuthAuthorizeToken) (*osin.AuthorizeData, error) {
	user, err := convertFromToken(authorize.UserName, authorize.UserUID)
	if err != nil {
		return nil, err
	}
	client, err := s.client.Get(context.TODO(), authorize.ClientName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if err := scopemetadata.ValidateScopeRestrictions(client, authorize.Scopes...); err != nil {
		return nil, err
	}

	return &osin.AuthorizeData{
		Code:                code,
		CodeChallenge:       authorize.CodeChallenge,
		CodeChallengeMethod: authorize.CodeChallengeMethod,
		Client:              &clientWrapper{authorize.ClientName, client, newTokenReviewer(s.tokenReview)},
		ExpiresIn:           int32(authorize.ExpiresIn),
		Scope:               scopecovers.Join(authorize.Scopes),
		RedirectUri:         authorize.RedirectURI,
		State:               authorize.State,
		CreatedAt:           authorize.CreationTimestamp.Time,
		UserData:            user,
	}, nil
}

func (s *storage) convertToAccessToken(data *osin.AccessData) (*oauthapi.OAuthAccessToken, error) {
	token := &oauthapi.OAuthAccessToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: TokenToObjectName(data.AccessToken),
			// creation time is controlled by the API
			// CreationTimestamp: metav1.Time{Time: data.CreatedAt},
		},
		ExpiresIn:    int64(data.ExpiresIn),
		RefreshToken: data.RefreshToken,
		ClientName:   data.Client.GetId(),
		Scopes:       scopecovers.Split(data.Scope),
		RedirectURI:  data.RedirectUri,
	}
	if data.AuthorizeData != nil {
		token.AuthorizeToken = data.AuthorizeData.Code
	}
	var err error
	if token.UserName, token.UserUID, err = convertFromUser(data.UserData); err != nil {
		return nil, err
	}

	token.InactivityTimeoutSeconds = s.tokentimeout
	// Check if we have a client specific inactivity Timeout to set
	if w, ok := data.Client.(handlers.TokenTimeoutSeconds); ok {
		if tt := w.GetAccessTokenInactivityTimeoutSeconds(); tt != nil {
			token.InactivityTimeoutSeconds = *tt
		}
	}

	return token, nil
}

func (s *storage) convertFromAccessToken(code string, access *oauthapi.OAuthAccessToken) (*osin.AccessData, error) {
	user, err := convertFromToken(access.UserName, access.UserUID)
	if err != nil {
		return nil, err
	}
	client, err := s.client.Get(context.TODO(), access.ClientName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if err := scopemetadata.ValidateScopeRestrictions(client, access.Scopes...); err != nil {
		return nil, err
	}

	return &osin.AccessData{
		AccessToken:  code,
		RefreshToken: access.RefreshToken,
		Client:       &clientWrapper{access.ClientName, client, newTokenReviewer(s.tokenReview)},
		ExpiresIn:    int32(access.ExpiresIn),
		Scope:        scopecovers.Join(access.Scopes),
		RedirectUri:  access.RedirectURI,
		CreatedAt:    access.CreationTimestamp.Time,
		UserData:     user,
	}, nil
}

func convertFromUser(user interface{}) (name, uid string, err error) {
	info, ok := user.(kuser.Info)
	if !ok {
		return "", "", fmt.Errorf("did not receive user.Info: %#v", user) // should be impossible
	}

	name = info.GetName()
	uid = info.GetUID()
	if len(name) == 0 || len(uid) == 0 {
		return "", "", fmt.Errorf("user.Info has no user name or UID: %#v", info) // should be impossible
	}

	return name, uid, nil
}

func convertFromToken(name, uid string) (kuser.Info, error) {
	if len(name) == 0 || len(uid) == 0 {
		return nil, fmt.Errorf("token has no user name or UID stored: name=%s uid=%s", name, uid) // should be impossible
	}

	return &kuser.DefaultInfo{
		Name: name,
		UID:  uid,
	}, nil
}

// TokenToObjectName returns the oauthaccesstokens object name for the given raw token,
// i.e. the sha256 hash prefixed with "sha256~".
func TokenToObjectName(code string) string {
	name, prefixed := crypto.TrimSHA256Prefix(code)
	if prefixed {
		return crypto.SHA256Token(name)
	}
	return name
}
