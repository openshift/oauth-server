package audit

import (
	"net/http"

	kaudit "k8s.io/apiserver/pkg/audit"
)

// Decision is made with regards to authentication.
type Decision string

const (
	// UsernameAnnotation is an annotation key for the username used for audit
	// events.
	UsernameAnnotation = "authentication.openshift.io/username"
	// DecisionAnnotation is an annotation key for the authentication decision
	// used for audit events.
	DecisionAnnotation = "authentication.openshift.io/decision"

	// AllowDecision is logged on a successful authentication.
	AllowDecision Decision = "allow"
	// DenyDecision is logged on an unsuccessful authentication attempt.
	DenyDecision Decision = "deny"
	// ErrorDecision is logged on errors that might not relate to the
	// authentication itself.
	ErrorDecision Decision = "error"
)

// AddDecisionAnnotation adds an authentication decision to the audit event. It
// is used at best at last. So after the last identity provider gets checked as
// if the first fails, and the last succeeds, you can't change the decision
// anymore.
func AddDecisionAnnotation(req *http.Request, decision Decision) {
	kaudit.AddAuditAnnotation(req.Context(), DecisionAnnotation, string(decision))
}

// AddUsernameAnnotation adds the username that attempts to authenticate to the
// audit event. It is used at best at the moment we parse the username. It can't
// be handled down through an authenticator.Response as this one get erased on
// `!ok` or `err != nil` case.
func AddUsernameAnnotation(req *http.Request, username string) {
	kaudit.AddAuditAnnotation(req.Context(), UsernameAnnotation, username)
}
