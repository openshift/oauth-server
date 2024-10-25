package oauthserver_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

	for _, tt := range []struct {
		name                 string
		providers            []osinv1.IdentityProvider
		clientPathEscapeFunc func(string) string
	}{
		{
			name: "single login provider",
			providers: []osinv1.IdentityProvider{
				newProvider("idp-no-spaces"),
			},
		},
		{
			name: "single login provider with spaces in name",
			providers: []osinv1.IdentityProvider{
				newProvider("idp with spaces"),
			},
		},
		{
			name: "multiple login providers",
			providers: []osinv1.IdentityProvider{
				newProvider("idp-no-spaces"),
				newProvider("idp-no-spaces-2"),
			},
		},
		{
			name: "multiple login providers with spaces in name",
			providers: []osinv1.IdentityProvider{
				newProvider("idp-no-spaces"),
				newProvider("idp with spaces"),
			},
		},
		{
			name: "multiple login providers with spaces in name and escaped in client",
			providers: []osinv1.IdentityProvider{
				newProvider("idp-no-spaces"),
				newProvider("idp with spaces"),
			},
			clientPathEscapeFunc: func(path string) string {
				return strings.ReplaceAll(path, " ", "%20")
			},
		},
		{
			name: "multiple login providers with %20 in name",
			providers: []osinv1.IdentityProvider{
				newProvider("idp-no-spaces"),
				newProvider("idp%20with%20spaces"),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oauthServerConfig.ExtraOAuthConfig.Options = osinv1.OAuthConfig{
				LoginURL:          "/login",
				IdentityProviders: tt.providers,
				GrantConfig: osinv1.GrantConfig{
					Method: osinv1.GrantHandlerAuto,
				},
			}

			h, err := oauthServerConfig.WithOAuth(http.NewServeMux())
			if err != nil {
				t.Errorf("got error while not expecting one: %v", err)
			}

			for _, p := range tt.providers {
				loginPath := "/login"
				if len(tt.providers) > 1 {
					loginPath += "/" + p.Name
				}

				for method, expectedStatus := range expectMethodStatus {
					path := loginPath
					if tt.clientPathEscapeFunc != nil {
						path = tt.clientPathEscapeFunc(path)
					}

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
		})
	}
}

func newProvider(name string) osinv1.IdentityProvider {
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
