package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	kaudit "k8s.io/apiserver/pkg/audit"

	"github.com/openshift/osin"
)

func TestAuthenticator(t *testing.T) {
	testCases := map[osin.AccessRequestType]struct {
		ExpectedAuthorized bool
		ExpectedError      bool
	}{
		osin.AUTHORIZATION_CODE: {true, false},
		osin.REFRESH_TOKEN:      {true, false},
		osin.PASSWORD:           {false, false},
		osin.ASSERTION:          {false, false},
		osin.CLIENT_CREDENTIALS: {false, false},
		osin.IMPLICIT:           {false, false},
	}

	for requestType, testCase := range testCases {
		httpReq, err := http.NewRequest(http.MethodPost, "https://example.org", nil)
		if err != nil {
			t.Fatal(err)
		}
		httpReq = httpReq.WithContext(kaudit.WithAuditContext(httpReq.Context()))
		req := &osin.AccessRequest{
			Type:        requestType,
			HttpRequest: httpReq,
		}
		w := httptest.NewRecorder()
		err = NewDenyAccessAuthenticator().HandleAccess(req, w)
		if testCase.ExpectedError && err == nil {
			t.Fatalf("%s: Expected error, got success", requestType)
		}
		if !testCase.ExpectedError && err != nil {
			t.Fatalf("%s: Unexpected error: %s", requestType, err)
		}
		if req.Authorized != testCase.ExpectedAuthorized {
			t.Fatalf("%s: Expected Authorized=%t, got Authorized=%t", requestType, testCase.ExpectedAuthorized, req.Authorized)
		}
	}
}

func TestDenyPassword(t *testing.T) {
	user, ok, err := deny.AuthenticatePassword(context.TODO(), "", "")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("Unexpected success")
	}
	if user != nil {
		t.Fatalf("Unexpected user info: %v", user)
	}
}

func TestDenyAssertion(t *testing.T) {
	user, ok, err := deny.AuthenticateAssertion("", "")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("Unexpected success")
	}
	if user != nil {
		t.Fatalf("Unexpected user info: %v", user)
	}
}

func TestDenyClient(t *testing.T) {
	user, ok, err := deny.AuthenticateClient(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("Unexpected success")
	}
	if user != nil {
		t.Fatalf("Unexpected user info: %v", user)
	}
}
