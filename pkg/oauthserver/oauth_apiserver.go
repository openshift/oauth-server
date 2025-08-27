package oauthserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	genericapiserver "k8s.io/apiserver/pkg/server"
	kclientset "k8s.io/client-go/kubernetes"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	osinv1 "github.com/openshift/api/osin/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
	userclientv1 "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	userinformerv1 "github.com/openshift/client-go/user/informers/externalversions/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/oauth/usercache"
	"github.com/openshift/oauth-server/pkg/config"
	"github.com/openshift/oauth-server/pkg/server/crypto"
	"github.com/openshift/oauth-server/pkg/server/headers"
	"github.com/openshift/oauth-server/pkg/server/session"
	"github.com/openshift/oauth-server/pkg/userregistry/identitymapper"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

// TODO we need to switch the oauth server to an external type, but that can be done after we get our externally facing flag values fixed
// TODO remaining bits involve the session file, LDAP util code, validation, ...
func NewOAuthServerConfig(oauthConfig osinv1.OAuthConfig, userClientConfig *rest.Config, genericConfig *genericapiserver.RecommendedConfig) (*OAuthServerConfig, error) {
	// TODO: there is probably some better way to do this
	decoder := codecs.UniversalDecoder(osinv1.GroupVersion)
	for i, idp := range oauthConfig.IdentityProviders {
		if idp.Provider.Object != nil {
			// depending on how you get here, the IDP objects may or may not be filled out
			break
		}
		idpObject, err := runtime.Decode(decoder, idp.Provider.Raw)
		if err != nil {
			return nil, err
		}
		oauthConfig.IdentityProviders[i].Provider.Object = idpObject
	}

	// this leaves the embedded OAuth server code path alone
	if genericConfig == nil {
		genericConfig = genericapiserver.NewRecommendedConfig(codecs)
	}

	genericConfig.LoopbackClientConfig = userClientConfig

	userClient, err := userclient.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	eventsClient, err := corev1.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	routeClient, err := routeclient.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kclientset.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}

	bootstrapUserDataGetter := bootstrap.NewBootstrapUserDataGetter(kubeClient.CoreV1(), kubeClient.CoreV1())

	var sessionAuth session.SessionAuthenticator
	if oauthConfig.SessionConfig != nil {
		// TODO we really need to enforce HTTPS always
		secure := isHTTPS(oauthConfig.MasterPublicURL)
		auth, err := buildSessionAuth(secure, oauthConfig.SessionConfig, bootstrapUserDataGetter)
		if err != nil {
			return nil, err
		}
		sessionAuth = auth

		// session capability is the only thing required to enable the bootstrap IDP
		// we dynamically enable or disable its UI based on the backing secret
		// this must be the first IDP to make sure that it can handle basic auth challenges first
		// this mostly avoids weird cases with the allow all IDP
		if bootstrapUserEnabled, err := bootstrapUserDataGetter.IsEnabled(); err != nil {
			return nil, err
		} else if bootstrapUserEnabled {
			oauthConfig.IdentityProviders = append(
				[]osinv1.IdentityProvider{
					{
						Name: bootstrap.BootstrapUser, // will never conflict with other IDPs due to the :
						// don't set it up as challenger if RequestHeaders IdP already is set that way
						// this would set challenging headers and break RequestHeaders IdP
						UseAsChallenger: !isRequestHeaderSetAsChallenger(oauthConfig.IdentityProviders),
						UseAsLogin:      true,
						MappingMethod:   string(identitymapper.MappingMethodClaim), // irrelevant, but needs to be valid
						Provider: runtime.RawExtension{
							Object: &config.BootstrapIdentityProvider{},
						},
					},
				},
				oauthConfig.IdentityProviders...,
			)
		}
	}

	if len(oauthConfig.IdentityProviders) == 0 {
		oauthConfig.IdentityProviders = []osinv1.IdentityProvider{
			{
				Name:            "defaultDenyAll",
				UseAsChallenger: true,
				UseAsLogin:      true,
				MappingMethod:   string(identitymapper.MappingMethodClaim),
				Provider: runtime.RawExtension{
					Object: &osinv1.DenyAllPasswordIdentityProvider{},
				},
			},
		}
	}

	userInformer := userinformer.NewSharedInformerFactory(userClient, time.Second*30)
	if err := userInformer.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
		usercache.ByUserIndexName: usercache.ByUserIndexKeys,
	}); err != nil {
		return nil, err
	}

	ret := &OAuthServerConfig{
		GenericConfig: genericConfig,
		ExtraOAuthConfig: ExtraOAuthConfig{
			Options:                        oauthConfig,
			KubeClient:                     kubeClient,
			EventsClient:                   eventsClient.Events(""),
			RouteClient:                    routeClient,
			UserClient:                     userClient.UserV1().Users(),
			GroupClient:                    userClient.UserV1().Groups(),
			GroupLister:                    userInformer.User().V1().Groups().Lister(),
			GroupInformer:                  userInformer.User().V1().Groups(),
			IdentityClient:                 userClient.UserV1().Identities(),
			UserIdentityMappingClient:      userClient.UserV1().UserIdentityMappings(),
			OAuthAccessTokenClient:         oauthClient.OAuthAccessTokens(),
			OAuthAuthorizeTokenClient:      oauthClient.OAuthAuthorizeTokens(),
			OAuthClientClient:              oauthClient.OAuthClients(),
			OAuthClientAuthorizationClient: oauthClient.OAuthClientAuthorizations(),
			SessionAuth:                    sessionAuth,
			BootstrapUserDataGetter:        bootstrapUserDataGetter,
			TokenReviewClient:              kubeClient.AuthenticationV1().TokenReviews(),

			postStartHooks: map[string]genericapiserver.PostStartHookFunc{
				"openshift.io-StartUserInformer": func(ctx genericapiserver.PostStartHookContext) error {
					go userInformer.Start(ctx.Done())
					return nil
				},
			},
		},
	}
	genericConfig.BuildHandlerChainFunc = ret.buildHandlerChainForOAuth

	return ret, nil
}

func buildSessionAuth(secure bool, config *osinv1.SessionConfig, getter bootstrap.BootstrapUserDataGetter) (session.SessionAuthenticator, error) {
	secrets, err := getSessionSecrets(config.SessionSecretsFile)
	if err != nil {
		return nil, err
	}
	sessionStore := session.NewStore(config.SessionName, secure, secrets...)
	sessionAuthenticator := session.NewAuthenticator(sessionStore, time.Duration(config.SessionMaxAgeSeconds)*time.Second)
	return session.NewBootstrapAuthenticator(sessionAuthenticator, getter, sessionStore), nil
}

func getSessionSecrets(filename string) ([][]byte, error) {
	// Build secrets list
	var secrets [][]byte

	if len(filename) != 0 {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		jsonData, err := yaml.ToJSON(data)
		if err != nil {
			// probably just json already
			jsonData = data
		}
		sessionSecrets := &osinv1.SessionSecrets{}
		if err := json.NewDecoder(bytes.NewBuffer(jsonData)).Decode(sessionSecrets); err != nil {
			return nil, fmt.Errorf("error reading sessionSecretsFile %s: %v", filename, err)
		}

		if len(sessionSecrets.Secrets) == 0 {
			return nil, fmt.Errorf("sessionSecretsFile %s contained no secrets", filename)
		}

		for _, s := range sessionSecrets.Secrets {
			// TODO make these length independent
			secrets = append(secrets, []byte(s.Authentication))
			secrets = append(secrets, []byte(s.Encryption))
		}
	} else {
		// Generate random signing and encryption secrets if none are specified in config
		const (
			sha256KeyLenBits = sha256.BlockSize * 8 // max key size with HMAC SHA256
			aes256KeyLenBits = 256                  // max key size with AES (AES-256)
		)
		secrets = append(secrets, crypto.RandomBits(sha256KeyLenBits))
		secrets = append(secrets, crypto.RandomBits(aes256KeyLenBits))
	}

	return secrets, nil
}

// isHTTPS returns true if the given URL is a valid https URL
func isHTTPS(u string) bool {
	parsedURL, err := url.Parse(u)
	return err == nil && parsedURL.Scheme == "https"
}

func isRequestHeaderSetAsChallenger(providers []osinv1.IdentityProvider) bool {
	for _, p := range providers {
		if _, isRequestHeader := p.Provider.Object.(*osinv1.RequestHeaderIdentityProvider); isRequestHeader && p.UseAsChallenger {
			return true
		}
	}
	return false
}

type ExtraOAuthConfig struct {
	Options osinv1.OAuthConfig

	// KubeClient is kubeclient with enough permission for the auth API
	KubeClient kclientset.Interface

	// EventsClient is for creating user events
	EventsClient corev1.EventInterface

	// RouteClient provides a client for OpenShift routes API.
	RouteClient routeclient.RouteV1Interface

	UserClient                userclientv1.UserInterface
	GroupClient               userclientv1.GroupInterface
	GroupLister               userlisterv1.GroupLister
	IdentityClient            userclientv1.IdentityInterface
	UserIdentityMappingClient userclientv1.UserIdentityMappingInterface

	GroupInformer userinformerv1.GroupInformer

	OAuthAccessTokenClient         oauthclient.OAuthAccessTokenInterface
	OAuthAuthorizeTokenClient      oauthclient.OAuthAuthorizeTokenInterface
	OAuthClientClient              oauthclient.OAuthClientInterface
	OAuthClientAuthorizationClient oauthclient.OAuthClientAuthorizationInterface

	SessionAuth session.SessionAuthenticator

	BootstrapUserDataGetter bootstrap.BootstrapUserDataGetter
	TokenReviewClient       authenticationv1client.TokenReviewInterface

	postStartHooks map[string]genericapiserver.PostStartHookFunc
}

type OAuthServerConfig struct {
	GenericConfig    *genericapiserver.RecommendedConfig
	ExtraOAuthConfig ExtraOAuthConfig
}

// OAuthServer serves non-API endpoints for openshift.
type OAuthServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer

	PublicURL url.URL
}

type completedOAuthConfig struct {
	GenericConfig    genericapiserver.CompletedConfig
	ExtraOAuthConfig *ExtraOAuthConfig
}

type CompletedOAuthConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedOAuthConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *OAuthServerConfig) Complete() completedOAuthConfig {
	cfg := completedOAuthConfig{
		c.GenericConfig.Complete(),
		&c.ExtraOAuthConfig,
	}

	return cfg
}

// this server is odd.  It doesn't delegate.  We mostly leave it alone, so I don't plan to make it look "normal".  We'll
// model it as a separate API server to reason about its handling chain, but otherwise, just let it be
func (c completedOAuthConfig) New(delegationTarget genericapiserver.DelegationTarget) (*OAuthServer, error) {
	genericServer, err := c.GenericConfig.New("openshift-oauth", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &OAuthServer{
		GenericAPIServer: genericServer,
	}

	for hookname, hook := range c.ExtraOAuthConfig.postStartHooks {
		if err := s.GenericAPIServer.AddPostStartHook(hookname, hook); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (c *OAuthServerConfig) buildHandlerChainForOAuth(startingHandler http.Handler, genericConfig *genericapiserver.Config) http.Handler {
	// add OAuth handlers on top of the generic API server handlers
	handler, err := c.WithOAuth(startingHandler)
	if err != nil {
		// the existing errors all cause the OAuth server to die anyway
		panic(err)
	}

	// restore the Authorization and any extra provider headers
	handler = headers.WithRestoreOAuthHeaders(handler, c.ExtraOAuthConfig.Options)

	// this is the normal kube handler chain
	handler = genericapiserver.DefaultBuildHandlerChain(handler, genericConfig)

	// store a copy of the Authorization and any extra provider headers for later use
	handler = headers.WithPreserveOAuthHeaders(handler, c.ExtraOAuthConfig.Options)

	// protected endpoints should not be cached
	handler = headers.WithStandardHeaders(handler)

	return handler
}
