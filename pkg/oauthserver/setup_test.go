package oauthserver_test

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakekube "k8s.io/client-go/kubernetes/fake"

	oauthv1 "github.com/openshift/api/oauth/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	fakeoauthclient "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	typedv1 "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	fakeuserclient "github.com/openshift/client-go/user/clientset/versioned/fake"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"

	"github.com/openshift/oauth-server/pkg/config"
	"github.com/openshift/oauth-server/pkg/oauthserver"
	"github.com/openshift/oauth-server/pkg/userregistry/identitymapper"
)

const (
	testPassword = "testpasswordxtestpasswordx" // must have at least len 23

	testClientName = "my_client"
)

var authorizeURL = "/oauth/authorize?client_id=" + testClientName +
	"&response_type=code"

func withAuth(req *http.Request, username, password string) {
	req.SetBasicAuth(username, password)
}

type mockBootstrapUser func() (*bootstrap.BootstrapUserData, bool, error)

var _ bootstrap.BootstrapUserDataGetter = (*mockBootstrapUser)(nil)

func (b mockBootstrapUser) IsEnabled() (bool, error) {
	return true, nil
}

func (b mockBootstrapUser) Get() (*bootstrap.BootstrapUserData, bool, error) {
	return b()
}

func kubeAdmin(t *testing.T, passwordHash []byte, auth bool, err error) mockBootstrapUser {
	return func() (*bootstrap.BootstrapUserData, bool, error) {
		hash, err := bcrypt.GenerateFromPassword(passwordHash, bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}

		return &bootstrap.BootstrapUserData{
			PasswordHash: hash,
			UID:          "kubeadmin-user-id",
		}, auth, err
	}
}

func setup(t *testing.T) http.Handler {
	kubeClient := fakekube.NewSimpleClientset()
	oauthClient := goodClientRegistry(
		testClientName,
		[]string{"myredirect"},
		[]string{"myscope1", "myscope2"},
	)
	kubeAdminIDP := kubeAdmin(t, []byte(testPassword), true, nil)
	informer := userinformer.NewSharedInformerFactory(
		fakeuserclient.NewSimpleClientset(),
		time.Second*30,
	)

	opts := osinv1.OAuthConfig{
		LoginURL: "/oauth/login",
		IdentityProviders: []osinv1.IdentityProvider{
			{
				Name:            bootstrap.BootstrapUser, // aka kube:admin
				UseAsChallenger: false,
				UseAsLogin:      false,
				MappingMethod:   string(identitymapper.MappingMethodClaim), // irrelevant, but needs to be valid
				Provider: runtime.RawExtension{
					Object: &config.BootstrapIdentityProvider{},
				},
			},
		},
		GrantConfig: osinv1.GrantConfig{
			Method: osinv1.GrantHandlerAuto,
		},
	}

	oauthServerConfig := oauthserver.OAuthServerConfig{
		ExtraOAuthConfig: oauthserver.ExtraOAuthConfig{
			KubeClient:              kubeClient,
			OAuthClientClient:       oauthClient,
			Options:                 opts,
			BootstrapUserDataGetter: kubeAdminIDP,
			GroupInformer:           informer.User().V1().Groups(),
		},
	}

	h, err := oauthServerConfig.WithOAuth(http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}

	return h
}

func goodClientRegistry(
	clientID string,
	redirectURIs []string,
	literalScopes []string,
) typedv1.OAuthClientInterface {
	client := &oauthv1.OAuthClient{
		ObjectMeta:   metav1.ObjectMeta{Name: clientID},
		Secret:       "mysecret",
		RedirectURIs: redirectURIs,
	}
	if len(literalScopes) > 0 {
		client.ScopeRestrictions = []oauthv1.ScopeRestriction{{ExactValues: literalScopes}}
	}
	fakeOAuthClient := fakeoauthclient.NewSimpleClientset(client)

	return fakeOAuthClient.OauthV1().OAuthClients()
}
