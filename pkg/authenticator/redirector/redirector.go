package redirector

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/openshift/oauth-server/pkg/authenticator/tokens"
	oauthhandlers "github.com/openshift/oauth-server/pkg/oauth/handlers"
)

// NewRedirector returns an oauthhandlers.AuthenticationRedirector that redirects to the specified redirectURL.
// Request URLs missing scheme/host, or with relative paths are resolved relative to the baseRequestURL, if specified.
// The following tokens are replaceable in the query of the redirectURL:
//
//	${url} is replaced with the current request URL, escaped as a query parameter. Example: https://www.example.com/login?then=${url}
//	${query} is replaced with the current request query, unescaped. Example: https://www.example.com/sso/oauth/authorize?${query}
func NewRedirector(baseRequestURL *url.URL, redirectURL string) oauthhandlers.AuthenticationRedirector {
	return &redirector{BaseRequestURL: baseRequestURL, RedirectURL: redirectURL}
}

// NewChallenger returns an oauthhandlers.AuthenticationChallenger that returns a Location header to the specified redirectURL.
// Request URLs missing scheme/host, or with relative paths are resolved relative to the baseRequestURL, if specified.
// The following tokens are replaceable in the query of the redirectURL:
//
//	${url} is replaced with the current request URL, escaped as a query parameter. Example: https://www.example.com/login?then=${url}
//	${query} is replaced with the current request query, unescaped. Example: https://www.example.com/sso/oauth/authorize?${query}
func NewChallenger(baseRequestURL *url.URL, redirectURL string) oauthhandlers.AuthenticationChallenger {
	return &redirector{BaseRequestURL: baseRequestURL, RedirectURL: redirectURL}
}

type redirector struct {
	BaseRequestURL *url.URL
	RedirectURL    string
}

// AuthenticationChallenge returns a Location header to the configured RedirectURL (which should return a challenge)
func (r *redirector) AuthenticationChallenge(req *http.Request) (http.Header, error) {
	redirectURL, err := buildRedirectURL(r.RedirectURL, r.BaseRequestURL, req.URL)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Add("Location", redirectURL.String())
	return headers, nil
}

// AuthenticationRedirect redirects to the configured RedirectURL
func (r *redirector) AuthenticationRedirect(w http.ResponseWriter, req *http.Request) error {
	redirectURL, err := buildRedirectURL(r.RedirectURL, r.BaseRequestURL, req.URL)
	if err != nil {
		return nil
	}
	http.Redirect(w, req, redirectURL.String(), http.StatusFound)
	return nil
}

func buildRedirectURL(redirectTemplate string, baseRequestURL, requestURL *url.URL) (*url.URL, error) {
	if baseRequestURL != nil {
		requestURL = baseRequestURL.ResolveReference(requestURL)
	}
	redirectURL, err := url.Parse(redirectTemplate)
	if err != nil {
		return nil, err
	}
	serverRelativeRequestURL := &url.URL{
		Path:     requestURL.Path,
		RawQuery: requestURL.RawQuery,
	}
	redirectURL.RawQuery = strings.Replace(redirectURL.RawQuery, tokens.QueryToken, requestURL.RawQuery, -1)
	redirectURL.RawQuery = strings.Replace(redirectURL.RawQuery, tokens.URLToken, url.QueryEscape(requestURL.String()), -1)
	redirectURL.RawQuery = strings.Replace(redirectURL.RawQuery, tokens.ServerRelativeURLToken, url.QueryEscape(serverRelativeRequestURL.String()), -1)
	return redirectURL, nil
}
