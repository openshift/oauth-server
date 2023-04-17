package oauthserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openshift/oauth-server/pkg/audit"

	kaudit "k8s.io/apiserver/pkg/audit"
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
