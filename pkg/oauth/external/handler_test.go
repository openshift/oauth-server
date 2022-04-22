package external

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RangelReale/osincli"

	auditapi "k8s.io/apiserver/pkg/apis/audit"
	kaudit "k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/oauth-server/pkg/audit"
	"github.com/openshift/oauth-server/pkg/oauth/handlers"
	"github.com/openshift/oauth-server/pkg/server/csrf"
)

func TestHandler(t *testing.T) {
	redirectors := new(handlers.AuthenticationRedirectors)
	redirectors.Add("handler", &Handler{})
	_ = handlers.NewUnionAuthenticationHandler(nil, redirectors, nil, nil)
}

func TestHandlerLoginAuditing(t *testing.T) {
	type checkFunc func(*auditapi.Event, authenticationHandler) error
	checks := func(fns ...checkFunc) []checkFunc { return fns }

	eventHasUsername := func(want string) checkFunc {
		return func(ev *auditapi.Event, _ authenticationHandler) error {
			have := ev.Annotations[audit.UsernameAnnotation]
			if want != have {
				return fmt.Errorf("expected username %q, found %q", want, have)
			}
			return nil
		}
	}

	eventHasDecision := func(want string) checkFunc {
		return func(ev *auditapi.Event, _ authenticationHandler) error {
			if have := ev.Annotations[audit.DecisionAnnotation]; want != have {
				return fmt.Errorf("expected decision %q, found %q", want, have)
			}
			return nil
		}
	}

	isAuthorized := func(_ *auditapi.Event, h authenticationHandler) error {
		if !h.success {
			return fmt.Errorf("expected call to success handler did not happen")
		}

		if h.failure {
			return fmt.Errorf("unexpected call to error handler")
		}

		return nil
	}

	isNotAuthorized := func(_ *auditapi.Event, h authenticationHandler) error {
		if !h.failure {
			return fmt.Errorf("expected call to error handler did not happen")
		}

		if h.success {
			return fmt.Errorf("unexpected call to success handler")
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
			username: "franta",
			err:      nil,
			checks: checks(
				eventHasUsername("franta"),
				eventHasDecision("allow"),
				isAuthorized,
			),
		},
		{
			name:     "error",
			username: "franta",
			err:      fmt.Errorf("identity provider error"),
			checks: checks(
				eventHasDecision("error"),
				isNotAuthorized,
			),
		},
		{
			name:     "unauthorized",
			username: "franta",
			err: &authError{
				msg:      "authorization error",
				username: "franta",
			},
			checks: checks(
				eventHasUsername("franta"),
				eventHasDecision("deny"),
				isNotAuthorized,
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authHandler := new(authenticationHandler)
			h := Handler{
				provider: provider{
					name:     "testprovider",
					username: tc.username,
					err:      tc.err,
				},
				mapper:       new(userIdentityMapper),
				success:      authHandler,
				errorHandler: authHandler,
			}

			req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/callback", nil)
			req = req.WithContext(kaudit.WithAuditAnnotations(req.Context()))

			h.authenticate(httptest.NewRecorder(), req, nil, "state")

			ev, err := kaudit.NewEventFromRequest(
				req, time.Now(),
				auditapi.LevelRequest,
				&authorizer.AttributesRecord{},
			)
			if err != nil {
				t.Fatalf("unexpected error in retrieving the audit events: %v", err)
			}

			for _, check := range tc.checks {
				if err := check(ev, *authHandler); err != nil {
					t.Error(err)
				}
			}
		})
	}
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
	Provider

	name     string
	username string
	err      error
}

func (p provider) GetUserIdentity(*osincli.AccessData) (api.UserIdentityInfo, error) {
	return userIdentityInfo{
		providerName: p.name,
		username:     p.username,
	}, p.err
}

type userIdentityInfo struct {
	providerName string
	username     string

	api.UserIdentityInfo
}

func (u userIdentityInfo) GetProviderPreferredUserName() string {
	return u.username
}

type userInfo struct {
	user.Info

	username string
}

func (u userInfo) GetName() string {
	return u.username
}

type userIdentityMapper struct{}

// UserFor takes an identity, ignores the passed identity.Provider, forces the provider value to some other value and then creates the mapping.
// It returns the corresponding user.Info
func (userIdentityMapper) UserFor(identityInfo api.UserIdentityInfo) (user.Info, error) {
	return userInfo{username: identityInfo.GetProviderPreferredUserName()}, nil
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

type authError struct {
	msg      string
	username string
}

func (err *authError) Username() string { return err.username }
func (err *authError) Error() string    { return err.msg }
