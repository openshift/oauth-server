package audit

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// AuthenticatorFunc is a Function that satisfies the authenticator.Request
// interface.
type AuthenticatorFunc func(*http.Request) (*authenticator.Response, bool, error)

var _ authenticator.Request = (*AuthenticatorFunc)(nil)

// AuthenticateRequest makes the func satisfy the authenticator.Request interface.
func (f AuthenticatorFunc) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return f(req)
}

// AuthenticatorRequestWithAudit annotates the audit log with the final decision of the
// union of authenticator.Requests. We can have several authenticator.Requesters hidden behind one
// and unified with union. If we set the decision on anything except the last, we will get a
// potentially wrong decision.
func AuthenticatorRequestWithAudit(authReq authenticator.Request) authenticator.Request {
	return AuthenticatorFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		res, ok, err := authReq.AuthenticateRequest(req)

		switch {
		case err != nil:
			AddDecisionAnnotation(req, ErrorDecision)
		case !ok:
			AddDecisionAnnotation(req, DenyDecision)
		case ok:
			AddDecisionAnnotation(req, AllowDecision)
		}

		if res != nil && res.User != nil {
			// This is only best effort. In the case of !ok or err, it won't have
			// values in most cases.
			AddUsernameAnnotation(req, res.User.GetName())
		}

		return res, ok, err
	})
}
