package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/osincli"
)

func TestGetUserIdentity(t *testing.T) {
	newGithubIdentityProvider := func(username string, orgs []string) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			body := new(bytes.Buffer)

			switch req.URL.Path {
			case "/user":
				if err := json.NewEncoder(body).Encode(struct {
					ID                 uint64
					Login, Email, Name string
				}{
					ID:    12345,
					Login: username,
					Email: "user@example.com",
				}); err != nil {
					panic(err)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     http.StatusText(http.StatusOK),
					Body:       io.NopCloser(body),
				}, nil

			case "/user/orgs":
				type ghOrg struct {
					ID    uint64
					Login string
				}
				ghOrgs := make([]ghOrg, len(orgs))
				for i := range orgs {
					ghOrgs[i] = ghOrg{
						ID:    999,
						Login: orgs[i],
					}

				}

				if err := json.NewEncoder(body).Encode(ghOrgs); err != nil {
					panic(err)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     http.StatusText(http.StatusOK),
					Body:       io.NopCloser(body),
				}, nil

			default:
				return nil, fmt.Errorf("this fixture does not serve the requested path: %s", req.URL.Path)
			}
		})
	}

	type checkFunc func(api.UserIdentityInfo, error) error
	hasUsername := func(want string) checkFunc {
		return func(userIdentityInfo api.UserIdentityInfo, _ error) error {
			if have := userIdentityInfo.GetProviderPreferredUserName(); want != have {
				return fmt.Errorf("expected username %q, got %q", want, have)
			}
			return nil
		}
	}
	hasUsernameInError := func(want string) checkFunc {
		return func(_ api.UserIdentityInfo, err error) error {
			var userIdentityInfo api.UserIdentityInfo

			var denied api.AuthorizationDeniedError
			if errors.As(err, &denied) {
				userIdentityInfo = denied.Identity()
			}

			var failed api.AuthorizationFailedError
			if errors.As(err, &failed) {
				userIdentityInfo = failed.Identity()
			}

			if have := userIdentityInfo.GetProviderPreferredUserName(); want != have {
				return fmt.Errorf("expected username %q, got %q", want, have)
			}
			return nil
		}
	}
	isAllowed := func(_ api.UserIdentityInfo, err error) error {
		if err != nil {
			return fmt.Errorf("unexpected error: %v", err)
		}
		return nil
	}
	isDenied := func(_ api.UserIdentityInfo, err error) error {
		if err == nil {
			return fmt.Errorf("expected authorization error, got nil")
		}
		var authError api.AuthorizationDeniedError
		if !errors.As(err, &authError) {
			return fmt.Errorf("expected authorization error, got %v", err)
		}
		return nil
	}

	for _, tc := range [...]struct {
		name                 string
		username             string
		userOrganizations    []string
		allowedOrganizations []string

		checks []checkFunc
	}{
		{
			name:     "ok",
			username: "hello",
			checks: []checkFunc{
				isAllowed,
				hasUsername("hello"),
			},
		},
		{
			name:                 "ok with organization check",
			username:             "hello",
			userOrganizations:    []string{"vip"},
			allowedOrganizations: []string{"vip"},
			checks: []checkFunc{
				isAllowed,
				hasUsername("hello"),
			},
		},
		{
			name:                 "ok with organization check, member of multiple",
			username:             "hello",
			userOrganizations:    []string{"openshift", "gophercloud", "vip", "kubernetes"},
			allowedOrganizations: []string{"vip"},
			checks: []checkFunc{
				isAllowed,
				hasUsername("hello"),
			},
		},
		{
			name:                 "ok with organization check, multiple allowed",
			username:             "hello",
			userOrganizations:    []string{"vip"},
			allowedOrganizations: []string{"vip", "openshift", "kubernetes"},
			checks: []checkFunc{
				isAllowed,
				hasUsername("hello"),
			},
		},
		{
			name:                 "denied, not in organization",
			username:             "hello",
			userOrganizations:    []string{"microsoft"},
			allowedOrganizations: []string{"neovim"},
			checks: []checkFunc{
				isDenied,
				hasUsernameInError("hello"),
			},
		},
		{
			name:                 "denied, not in any organization",
			username:             "hello",
			allowedOrganizations: []string{"vip"},
			checks: []checkFunc{
				isDenied,
				hasUsernameInError("hello"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userIdentityInfo, err := NewProvider(
				"git-tub",
				"my_client_id",
				"my_client_secret",
				"",
				newGithubIdentityProvider(tc.username, tc.userOrganizations),
				tc.allowedOrganizations,
				nil,
			).GetUserIdentity(&osincli.AccessData{})

			for _, check := range tc.checks {
				if e := check(userIdentityInfo, err); e != nil {
					t.Error(e)
				}
			}
		})
	}

}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rt roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}
