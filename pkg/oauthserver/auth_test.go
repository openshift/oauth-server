package oauthserver_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	osinv1 "github.com/openshift/api/osin/v1"
	fakeuserclient "github.com/openshift/client-go/user/clientset/versioned/fake"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	"github.com/openshift/oauth-server/pkg/audit"
	"github.com/openshift/oauth-server/pkg/oauthserver"
	"github.com/openshift/oauth-server/pkg/server/session"
	"github.com/openshift/oauth-server/pkg/userregistry/identitymapper"

	configv1 "github.com/openshift/api/config/v1"

	"k8s.io/apimachinery/pkg/runtime"
	kaudit "k8s.io/apiserver/pkg/audit"
	fakekube "k8s.io/client-go/kubernetes/fake"
)

// TestWithOAuth is currently only testing auditing and therefore heavily mocked.
// It is encouraged to reduce the mocking and test more parts of WithOAuth.
func TestWithOAuth(t *testing.T) {
	h := setup(t)

	for _, tc := range [...]struct {
		name     string
		given    *http.Request
		expected []annotationChecker
	}{
		{
			name: "should audit success for bootstrap user (kubeadmin) and good password",
			given: func() *http.Request {
				req := httptest.NewRequest(
					http.MethodGet,
					authorizeURL,
					nil,
				)
				req = req.WithContext(kaudit.WithAuditContext(req.Context()))

				withAuth(req, "kubeadmin", testPassword)
				return req
			}(),
			expected: []annotationChecker{
				withUsernameAnnotation("kubeadmin"),
				withDecisionAnnotation(string(audit.AllowDecision)),
			},
		},
		{
			name: "should audit deny by default",
			given: func() *http.Request {
				req := httptest.NewRequest(
					http.MethodGet,
					authorizeURL,
					nil,
				)
				req = req.WithContext(kaudit.WithAuditContext(req.Context()))

				return req
			}(),
			expected: []annotationChecker{
				withUsernameAnnotation(""),
				withDecisionAnnotation(string(audit.DenyDecision)),
			},
		},
		{
			name: "should audit deny on kubeadmin user with wrong password",
			given: func() *http.Request {
				req := httptest.NewRequest(
					http.MethodGet,
					authorizeURL,
					nil,
				)
				req = req.WithContext(kaudit.WithAuditContext(req.Context()))

				withAuth(req, "kubeadmin", "random-non-sense-non-sense")
				return req
			}(),
			expected: []annotationChecker{
				withUsernameAnnotation("kubeadmin"),
				withDecisionAnnotation(string(audit.DenyDecision)),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.given)

			res := rec.Result()
			if res.StatusCode != http.StatusFound {
				t.Error(res)
			}

			verifyAnnotations(t, tc.given, tc.expected)
		})
	}
}

func TestWithOAuth_loginProviders(t *testing.T) {
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

	oauthServerConfig := oauthserver.OAuthServerConfig{
		ExtraOAuthConfig: oauthserver.ExtraOAuthConfig{
			KubeClient:              kubeClient,
			OAuthClientClient:       oauthClient,
			BootstrapUserDataGetter: kubeAdminIDP,
			GroupInformer:           informer.User().V1().Groups(),
			SessionAuth:             session.NewAuthenticator(nil, 10*time.Minute),
		},
	}

	for _, tt := range []struct {
		name                 string
		providers            []osinv1.IdentityProvider
		clientPathEscapeFunc func(string) string
	}{
		{
			name: "single login provider",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-no-spaces"),
			},
		},
		{
			name: "single login provider with spaces in name",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp with spaces"),
			},
		},
		{
			name: "single oauth provider",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp-no-spaces"),
			},
		},
		{
			name: "single oauth provider with spaces in name",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp with spaces"),
			},
		},
		{
			name: "multiple login providers",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-no-spaces"),
				newLoginProvider("idp-no-spaces-2"),
			},
		},
		{
			name: "multiple login providers with spaces in name",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-no-spaces"),
				newLoginProvider("idp with spaces"),
			},
		},
		{
			name: "multiple login providers with spaces in name and escaped in client",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-no-spaces"),
				newLoginProvider("idp with spaces"),
			},
			clientPathEscapeFunc: func(path string) string {
				return strings.ReplaceAll(path, " ", "%20")
			},
		},
		{
			name: "multiple login providers with %20 in name",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-no-spaces"),
				newLoginProvider("idp%20with%20spaces"),
			},
		},
		{
			name: "multiple oauth providers",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp-no-spaces"),
				newOAuthProvider("idp-no-spaces-2"),
			},
		},
		{
			name: "multiple oauth providers with spaces in name",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp-no-spaces"),
				newOAuthProvider("idp with spaces"),
			},
		},
		{
			name: "multiple oauth providers with spaces in name and escaped in client",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp-no-spaces"),
				newOAuthProvider("idp with spaces"),
			},
			clientPathEscapeFunc: func(path string) string {
				return strings.ReplaceAll(path, " ", "%20")
			},
		},
		{
			name: "multiple oauth providers with %20 in name",
			providers: []osinv1.IdentityProvider{
				newOAuthProvider("idp-no-spaces"),
				newOAuthProvider("idp%20with%20spaces"),
			},
		},
		{
			name: "one login and one oauth provider without spaces",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-login"),
				newOAuthProvider("idp-oauth"),
			},
		},
		{
			name: "one login and one oauth provider with spaces",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp login"),
				newOAuthProvider("idp oauth"),
			},
		},
		{
			name: "multiple login and multiple oauth provider without spaces",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp-login1"),
				newLoginProvider("idp-login2"),
				newOAuthProvider("idp-oauth1"),
				newOAuthProvider("idp-oauth2"),
			},
		},
		{
			name: "multiple login and multiple oauth provider with spaces",
			providers: []osinv1.IdentityProvider{
				newLoginProvider("idp login 1"),
				newLoginProvider("idp login 2"),
				newOAuthProvider("idp oauth 1"),
				newOAuthProvider("idp oauth 2"),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oauthServerConfig.ExtraOAuthConfig.Options = osinv1.OAuthConfig{
				IdentityProviders: tt.providers,
				GrantConfig: osinv1.GrantConfig{
					Method: osinv1.GrantHandlerAuto,
				},
			}

			h, err := oauthServerConfig.WithOAuth(http.NewServeMux())
			if err != nil {
				t.Errorf("got error while not expecting one: %v", err)
			}

			cntLoginProviders := 0
			for _, p := range tt.providers {
				if p.UseAsLogin {
					cntLoginProviders += 1
				}
			}

			for _, p := range tt.providers {
				if p.UseAsLogin {
					loginPath := "/login"
					if cntLoginProviders > 1 {
						loginPath += "/" + p.Name
					}

					if tt.clientPathEscapeFunc != nil {
						loginPath = tt.clientPathEscapeFunc(loginPath)
					}

					callLogin(t, &p, h, loginPath)

				} else if p.UseAsChallenger {
					callChallenger(t, &p, h)

				} else {
					t.Fatalf("provider '%s' neither login nor challenger", p.Name)
				}
			}
		})
	}
}

func callLogin(t *testing.T, p *osinv1.IdentityProvider, h http.Handler, loginPath string) {
	expectMethodStatus := map[string]int{
		http.MethodGet:     http.StatusFound,
		http.MethodPost:    http.StatusFound,
		http.MethodHead:    http.StatusMethodNotAllowed,
		http.MethodPut:     http.StatusMethodNotAllowed,
		http.MethodPatch:   http.StatusMethodNotAllowed,
		http.MethodDelete:  http.StatusMethodNotAllowed,
		http.MethodConnect: http.StatusMethodNotAllowed,
		http.MethodOptions: http.StatusMethodNotAllowed,
		http.MethodTrace:   http.StatusMethodNotAllowed,
	}

	for method, expectedStatus := range expectMethodStatus {
		t.Logf("sending '%s %s' to provider '%s'", method, loginPath, p.Name)
		rec := httptest.NewRecorder()
		req, err := http.NewRequest(method, loginPath, nil)
		if err != nil {
			t.Fatalf("error while creating request: %v", err)
		}

		h.ServeHTTP(rec, req)
		res := rec.Result()

		if expectedStatus != res.StatusCode {
			t.Errorf("expected HTTP status [%d %s]; got [%s]", expectedStatus, http.StatusText(expectedStatus), res.Status)
		}
	}
}

func callChallenger(t *testing.T, p *osinv1.IdentityProvider, h http.Handler) {
	// we expect a 500 because this won't be a valid oauth request; but this is
	// enough to validate that the handler was set up correctly
	expectedStatus := http.StatusInternalServerError
	path := path.Join("/oauth2callback", p.Name)

	for _, method := range []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodHead,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	} {
		t.Logf("sending '%s %s' to provider '%s'", method, path, p.Name)
		rec := httptest.NewRecorder()
		req, err := http.NewRequest(method, path, nil)
		if err != nil {
			t.Fatalf("error while creating request: %v", err)
		}

		h.ServeHTTP(rec, req)
		res := rec.Result()

		if expectedStatus != res.StatusCode {
			t.Errorf("expected HTTP status [%d %s]; got [%s]", expectedStatus, http.StatusText(expectedStatus), res.Status)
		}
	}
}

func newLoginProvider(name string) osinv1.IdentityProvider {
	return osinv1.IdentityProvider{
		Name:          name,
		UseAsLogin:    true,
		MappingMethod: string(identitymapper.MappingMethodClaim),
		Provider: runtime.RawExtension{
			Object: &osinv1.BasicAuthPasswordIdentityProvider{
				RemoteConnectionInfo: configv1.RemoteConnectionInfo{
					URL: fmt.Sprintf("https://%s.com", name),
				},
			},
		},
	}
}

func newOAuthProvider(name string) osinv1.IdentityProvider {
	return osinv1.IdentityProvider{
		Name:            name,
		UseAsChallenger: true,
		MappingMethod:   string(identitymapper.MappingMethodClaim),
		Provider: runtime.RawExtension{
			Object: &osinv1.OpenIDIdentityProvider{
				ClientID: "client-id",
				ClientSecret: configv1.StringSource{StringSourceSpec: configv1.StringSourceSpec{
					Value: "client-secret",
				}},
				URLs: osinv1.OpenIDURLs{
					Authorize: "https://provider.com/authorize",
					Token:     "https://provider.com/token",
				},
				Claims: osinv1.OpenIDClaims{
					ID: []string{"id-claim"},
				},
			},
		},
	}
}
