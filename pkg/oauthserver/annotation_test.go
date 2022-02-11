package oauthserver_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	apiaudit "k8s.io/apiserver/pkg/apis/audit"
	kaudit "k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/openshift/oauth-server/pkg/audit"
)

func withDecisionAnnotation(want string) func(*testing.T, map[string]string) {
	return func(t *testing.T, ano map[string]string) {
		if have, ok := ano[audit.DecisionAnnotation]; !ok || want != have {
			t.Error(fmt.Errorf(
				"want: %s for decision, have: %s for decision",
				want, have,
			))
		}
	}
}

func withUsernameAnnotation(want string) func(*testing.T, map[string]string) {
	return func(t *testing.T, ano map[string]string) {
		have, ok := ano[audit.UsernameAnnotation]
		valueExpected := len(want) > 0

		if !ok && valueExpected || want != have {
			t.Error(fmt.Errorf(
				"want: '%s' for username, have: '%s' for username and ok is %t",
				want, have, ok,
			))
		}
	}
}

type annotationChecker func(*testing.T, map[string]string)

func verifyAnnotations(t *testing.T, req *http.Request, checker []annotationChecker) {
	ev, err := kaudit.NewEventFromRequest(
		req, time.Now(),
		apiaudit.LevelRequestResponse,
		&authorizer.AttributesRecord{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ev.Annotations) == 0 {
		t.Error(errors.New("ev.Annotations is empty"))
	}

	for _, check := range checker {
		check(t, ev.Annotations)
	}
}
