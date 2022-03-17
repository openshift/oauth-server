package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/RangelReale/osincli"
	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/oauth-server/pkg/oauth/external"
)

func TestGetUserIdentity(t *testing.T) {
	newGithubIdentityProvider := func(userID uint64, orgs []string) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			body := new(bytes.Buffer)

			switch req.URL.Path {
			case "/user":
				if err := json.NewEncoder(body).Encode(struct {
					ID                 uint64
					Login, Email, Name string
				}{
					ID:    userID,
					Login: "loginname",
					Email: "user@example.com",
					Name:  "drago_tommasone",
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
	checks := func(fns ...checkFunc) []checkFunc { return fns }

	hasUserID := func(want string) checkFunc {
		return func(userIdentityInfo api.UserIdentityInfo, _ error) error {
			if have := userIdentityInfo.GetIdentityName(); want != have {
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
		var authError external.AuthorizationError
		if !errors.As(err, &authError) {
			return fmt.Errorf("expected authorization error, got %v", err)
		}
		return nil
	}
	throwsError := func(_ api.UserIdentityInfo, err error) error {
		if err == nil {
			return fmt.Errorf("expected error, got nil")
		}
		return nil
	}

	for _, tc := range [...]struct {
		name                 string
		userID               uint64
		userOrganizations    []string
		allowedOrganizations []string

		checks []checkFunc
	}{
		{
			name:   "ok",
			userID: 123654,
			checks: checks(
				isAllowed,
				hasUserID("git-tub:123654"),
			),
		},
		{
			name:                 "ok with organization check",
			userID:               564738,
			userOrganizations:    []string{"vip"},
			allowedOrganizations: []string{"vip"},
			checks: checks(
				isAllowed,
				hasUserID("git-tub:564738"),
			),
		},
		{
			name:                 "ok with organization check, member of multiple",
			userID:               564738,
			userOrganizations:    []string{"openshift", "gophercloud", "vip", "kubernetes"},
			allowedOrganizations: []string{"vip"},
			checks: checks(
				isAllowed,
				hasUserID("git-tub:564738"),
			),
		},
		{
			name:                 "ok with organization check, multiple allowed",
			userID:               564738,
			userOrganizations:    []string{"vip"},
			allowedOrganizations: []string{"vip", "openshift", "kubernetes"},
			checks: checks(
				isAllowed,
				hasUserID("git-tub:564738"),
			),
		},
		{
			name:                 "denied, not in organization",
			userID:               98765491,
			userOrganizations:    []string{"microsoft"},
			allowedOrganizations: []string{"neovim"},
			checks: checks(
				isDenied,
				hasUserID("git-tub:98765491"),
			),
		},
		{
			name:                 "denied, not in any organization",
			userID:               987654,
			allowedOrganizations: []string{"vip"},
			checks: checks(
				isDenied,
				hasUserID("git-tub:987654"),
			),
		},
		{
			name: "denied, no userID",
			checks: checks(
				throwsError,
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userIdentityInfo, err := NewProvider(
				"git-tub",
				"my_client_id",
				"my_client_secret",
				"",
				newGithubIdentityProvider(tc.userID, tc.userOrganizations),
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
