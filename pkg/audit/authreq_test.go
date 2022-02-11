package audit_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/openshift/oauth-server/pkg/audit"
	kaudit "k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// mustShallowRequestWithAnnotations could be extended with more features in the
// future and renamed to mustRequest. Currently it is just a template for a
// request with some URL and annotations context.
func mustShallowRequestWithAnnotations(t *testing.T) *http.Request {
	req, err := http.NewRequest(
		http.MethodPost,
		"https://oauth-server.openshift.com/authn",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	return req.WithContext(kaudit.WithAuditAnnotations(req.Context()))
}

func makeAuthReq(res *authenticator.Response, ok bool, err error) authenticator.Request {
	return audit.AuthenticatorFunc(func(_ *http.Request) (*authenticator.Response, bool, error) {
		return res, ok, err
	})
}

func TestAuthenticationRequestWithAuditDecision(t *testing.T) {
	for _, tt := range [...]struct {
		name string
		have authenticator.Request
		want map[string]string
	}{
		{
			name: "should audit allow decision",
			have: makeAuthReq(nil, true, nil),
			want: map[string]string{
				audit.DecisionAnnotation: string(audit.AllowDecision),
			},
		},
		{
			name: "should audit deny decision",
			have: makeAuthReq(nil, false, nil),
			want: map[string]string{
				audit.DecisionAnnotation: string(audit.DenyDecision),
			},
		},
		{
			name: "should audit error decision",
			have: makeAuthReq(nil, false, errors.New("expected error")),
			want: map[string]string{
				audit.DecisionAnnotation: string(audit.ErrorDecision),
			},
		},
		{
			name: "ambiguous authenticator both allowing and erroring",
			have: makeAuthReq(nil, true, errors.New("expected error")),
			want: map[string]string{
				audit.DecisionAnnotation: string(audit.ErrorDecision),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authReq := audit.AuthenticatorRequestWithAuditDecision(tt.have)
			req := mustShallowRequestWithAnnotations(t)

			_, _, _ = authReq.AuthenticateRequest(req)
			verifyAnnotations(t, req, tt.want)
		})
	}
}
