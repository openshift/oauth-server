package external

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/oauth-server/pkg/oauth/handlers"
	"github.com/openshift/oauth-server/pkg/server/csrf"
	"github.com/openshift/osincli"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestHandler(t *testing.T) {
	redirectors := new(handlers.AuthenticationRedirectors)
	redirectors.Add("handler", &Handler{})
	_ = handlers.NewUnionAuthenticationHandler(nil, redirectors, nil, nil)
}

func TestHandlerLogin(t *testing.T) {
	t.Run("audit", func(t *testing.T) {
		type checkFunc func(map[string]string, authenticationHandler, *userIdentityMapper) error

		eventHasUsername := func(want string) checkFunc {
			return func(annotations map[string]string, _ authenticationHandler, _ *userIdentityMapper) error {
				if have := annotations["authentication.openshift.io/username"]; want != have {
					return fmt.Errorf("expected username %q, found %q", want, have)
				}
				return nil
			}
		}
		eventHasDecision := func(want string) checkFunc {
			return func(annotations map[string]string, _ authenticationHandler, _ *userIdentityMapper) error {
				if have := annotations["authentication.openshift.io/decision"]; want != have {
					return fmt.Errorf("expected decision %q, found %q", want, have)
				}
				return nil
			}
		}
		isAuthorized := func(_ map[string]string, h authenticationHandler, _ *userIdentityMapper) error {
			if !h.success {
				return fmt.Errorf("expected call to success handler did not happen")
			}
			if h.failure {
				return fmt.Errorf("unexpected call to error handler")
			}
			return nil
		}
		isNotAuthorized := func(_ map[string]string, h authenticationHandler, _ *userIdentityMapper) error {
			if !h.failure {
				return fmt.Errorf("expected call to error handler did not happen")
			}
			if h.success {
				return fmt.Errorf("unexpected call to success handler")
			}
			return nil
		}
		mapperWasNotCalled := func(_ map[string]string, _ authenticationHandler, m *userIdentityMapper) error {
			if m.wasCalled {
				return fmt.Errorf("the identity mapper was called upon unsuccessful auth")
			}
			return nil
		}

		for _, tc := range [...]struct {
			name     string
			username string
			err      error
			checks   []checkFunc
		}{
			{
				name:     "authorized",
				username: "boucle_d_or",
				err:      nil,
				checks: []checkFunc{
					eventHasUsername("boucle_d_or"),
					eventHasDecision("allow"),
					isAuthorized,
				},
			},
			{
				name:     "error",
				username: "boucle_d_or",
				err:      fmt.Errorf("identity provider error"),
				checks: []checkFunc{
					eventHasDecision("error"),
					isNotAuthorized,
					mapperWasNotCalled,
				},
			},
			{
				name:     "unauthorized",
				username: "boucle_d_or",
				err: api.NewAuthorizationDeniedError(
					api.NewDefaultUserIdentityInfo("testprovider", "boucle_d_or"),
					errors.New("user not in group"),
				),
				checks: []checkFunc{
					eventHasUsername("boucle_d_or"),
					eventHasDecision("deny"),
					isNotAuthorized,
					mapperWasNotCalled,
				},
			},
			{
				name:     "error_with_username",
				username: "boucle_d_or",
				err: api.NewAuthorizationFailedError(
					api.NewDefaultUserIdentityInfo("testprovider", "boucle_d_or"),
					errors.New("user not in group"),
				),
				checks: []checkFunc{
					eventHasUsername("boucle_d_or"),
					eventHasDecision("error"),
					isNotAuthorized,
					mapperWasNotCalled,
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				authHandler := new(authenticationHandler)
				identityMapper := new(userIdentityMapper)
				h := Handler{
					provider: provider{
						name:     "testprovider",
						username: tc.username,
						err:      tc.err,
					},
					mapper:       identityMapper,
					success:      authHandler,
					errorHandler: authHandler,
				}

				req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/callback", nil)
				req = req.WithContext(audit.WithAuditContext(req.Context()))

				h.login(httptest.NewRecorder(), req, nil, "state")

				ac := audit.AuditContextFrom(req.Context())
				annotations := ac.GetEventAnnotations()
				for _, check := range tc.checks {
					if err := check(annotations, *authHandler, identityMapper); err != nil {
						t.Error(err)
					}
				}
			})
		}
	})
}

func TestRedirectingStateValidCSRF(t *testing.T) {
	fakeCSRF := &csrf.FakeCSRF{
		Token: "xyz",
	}
	redirectingState := CSRFRedirectingState(fakeCSRF)

	req, _ := http.NewRequest("GET", "http://www.example.com", nil)
	state, err := redirectingState.Generate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}

	// Make sure the state verifies
	req2, _ := http.NewRequest("GET", "http://www.example.com/callback", nil)
	ok, err := redirectingState.Check(state, req2)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if !ok {
		t.Fatalf("Unexpected invalid state")
	}
}

func TestRedirectingStateInvalidCSRF(t *testing.T) {
	fakeCSRF := &csrf.FakeCSRF{
		Token: "xyz",
	}
	redirectingState := CSRFRedirectingState(fakeCSRF)

	req, _ := http.NewRequest("GET", "http://www.example.com", nil)
	state, err := redirectingState.Generate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}

	req2, _ := http.NewRequest("GET", "http://www.example.com/callback", nil)

	// Initial check passes as valid with no error
	if ok, err := redirectingState.Check(state, req2); !ok || err != nil {
		t.Fatalf("Expected valid and no error, got: %v %v", ok, err)
	}

	// Change the CSRF validator so it returns invalid and an error
	fakeCSRF.Token = "abc"
	if ok, err := redirectingState.Check(state, req2); ok || err == nil {
		t.Fatalf("Expected invalid and error, got: %v %v", ok, err)
	}
}

func TestRedirectingStateSuccess(t *testing.T) {
	originalURL := "http://www.example.com"

	fakeCSRF := &csrf.FakeCSRF{
		Token: "xyz",
	}
	redirectingState := CSRFRedirectingState(fakeCSRF)

	req, _ := http.NewRequest("GET", originalURL, nil)
	state, err := redirectingState.Generate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}

	req2, _ := http.NewRequest("GET", "http://www.example.com/callback", nil)
	recorder := httptest.NewRecorder()
	user := &user.DefaultInfo{}

	handled, err := redirectingState.AuthenticationSucceeded(user, state, recorder, req2)
	if err != nil {
		t.Errorf("Unexpected error: %#v", err)
	}
	if !handled {
		t.Errorf("Expected handled request")
	}
	if recorder.Header().Get("Location") != originalURL {
		t.Errorf("Expected redirect to %s, got %#v", originalURL, recorder.Header())
	}
}

func TestRedirectingStateOAuthError(t *testing.T) {
	originalURL := "http://www.example.com"
	expectedURL := "http://www.example.com?error=access_denied"

	fakeCSRF := &csrf.FakeCSRF{
		Token: "xyz",
	}
	redirectingState := CSRFRedirectingState(fakeCSRF)

	req, _ := http.NewRequest("GET", originalURL, nil)
	state, err := redirectingState.Generate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}

	req2, _ := http.NewRequest("GET", "http://www.example.com/callback", nil)
	recorder := httptest.NewRecorder()
	osinErr := &osincli.Error{
		Id:    "access_denied",
		State: state,
	}

	handled, err := redirectingState.AuthenticationError(osinErr, recorder, req2)
	if err != nil {
		t.Errorf("Unexpected error: %#v", err)
	}
	if !handled {
		t.Errorf("Expected handled request")
	}
	if recorder.Header().Get("Location") != expectedURL {
		t.Errorf("Expected redirect to %s, got %#v", expectedURL, recorder.Header())
	}
}

func TestRedirectingStateError(t *testing.T) {
	fakeCSRF := &csrf.FakeCSRF{
		Token: "xyz",
	}
	redirectingState := CSRFRedirectingState(fakeCSRF)

	req2, _ := http.NewRequest("GET", "http://www.example.com/callback", nil)
	recorder := httptest.NewRecorder()
	inErr := errors.New("test")

	handled, err := redirectingState.AuthenticationError(inErr, recorder, req2)
	if handled {
		t.Errorf("Expected unhandled request")
	}
	if err != inErr {
		t.Errorf("Expected original error back, got %#v", err)
	}
}

type provider struct {
	name     string
	username string
	err      error
	Provider
}

func (p provider) GetUserIdentity(*osincli.AccessData) (api.UserIdentityInfo, error) {
	return &api.DefaultUserIdentityInfo{
		ProviderName:     p.name,
		ProviderUserName: p.username,
	}, p.err
}

type userIdentityMapper struct {
	wasCalled bool
}

func (m *userIdentityMapper) UserFor(identityInfo api.UserIdentityInfo) (user.Info, error) {
	m.wasCalled = true
	return &user.DefaultInfo{Name: identityInfo.GetProviderUserName()}, nil
}

type authenticationHandler struct {
	success bool
	failure bool
}

func (h *authenticationHandler) AuthenticationSucceeded(user.Info, string, http.ResponseWriter, *http.Request) (bool, error) {
	h.success = true
	return true, nil
}
func (h *authenticationHandler) AuthenticationError(error, http.ResponseWriter, *http.Request) (bool, error) {
	h.failure = true
	return true, nil
}
