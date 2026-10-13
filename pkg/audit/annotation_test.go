package audit_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	kaudit "k8s.io/apiserver/pkg/audit"

	"github.com/openshift/oauth-server/pkg/audit"
)

func verifyAnnotations(t *testing.T, req *http.Request, want map[string]string) {
	ac := kaudit.AuditContextFrom(req.Context())
	annotations := ac.GetEventAnnotations()

	if len(annotations) == 0 {
		t.Error(errors.New("annotations is empty"))
	}

	for k, v := range want {
		if ea, ok := annotations[k]; !ok || ea != v {
			t.Error(fmt.Errorf("have: %s, want: %s", ea, v))
		}
	}
}

func TestAddUsername(t *testing.T) {
	for _, tt := range [...]struct {
		name string
		have []string
		want map[string]string
	}{
		{
			name: "should annotate the username",
			have: []string{"kubeadmin"},
			want: map[string]string{
				audit.UsernameAnnotation: "kubeadmin",
			},
		},
		{
			name: "should annotate the first given username",
			have: []string{"system:unauthenticated", "kubeadmin"},
			want: map[string]string{
				audit.UsernameAnnotation: "system:unauthenticated",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := mustShallowRequestWithAnnotations(t)
			for _, username := range tt.have {
				audit.AddUsernameAnnotation(req, username)
			}

			verifyAnnotations(t, req, tt.want)
		})
	}
}

func decision(d audit.Decision) map[string]string {
	return map[string]string{
		audit.DecisionAnnotation: string(d),
	}
}

func decisions(a ...audit.Decision) []audit.Decision {
	return a
}

func TestAddDecision(t *testing.T) {
	var tests = []struct {
		name string
		have []audit.Decision
		want map[string]string
	}{
		{
			name: "should add 'allow' to decision in audit annotation",
			have: decisions(audit.AllowDecision),
			want: decision(audit.AllowDecision),
		},
		{
			name: "should add 'deny' to decision in audit annotation",
			have: decisions(audit.DenyDecision),
			want: decision(audit.DenyDecision),
		},
		{
			name: "should add 'error' to decision in audit annotation",
			have: decisions(audit.ErrorDecision),
			want: decision(audit.ErrorDecision),
		},
		{
			name: "should keep the first decision",
			have: decisions(audit.DenyDecision, audit.AllowDecision),
			want: decision(audit.DenyDecision),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustShallowRequestWithAnnotations(t)
			for _, decision := range tt.have {
				audit.AddDecisionAnnotation(req, decision)
			}

			verifyAnnotations(t, req, tt.want)
		})
	}
}
