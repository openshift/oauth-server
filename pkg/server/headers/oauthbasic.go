package headers

import (
	"net/http"

	osinv1 "github.com/openshift/api/osin/v1"
)

const (
	authzHeader      = "Authorization"
	headerCopyPrefix = "oauth.openshift.io:" // will never conflict because : is not a valid header key
)

func preservedHeaders(oauthConfig *osinv1.OAuthConfig) []string {
	// compile a list of headers that should be preserved lest any handler in the kube chain deletes them
	// so that WithOAuth can use them even after WithAuthentication deletes them
	// WithOAuth sees users' passwords and can mint tokens so this is not really an issue
	preservedHeaders := make([]string, 0)
	for _, identityProvider := range oauthConfig.IdentityProviders {
		switch provider := identityProvider.Provider.Object.(type) {
		case *osinv1.RequestHeaderIdentityProvider:
			preservedHeaders = append(preservedHeaders, provider.Headers...)
			preservedHeaders = append(preservedHeaders, provider.PreferredUsernameHeaders...)
			preservedHeaders = append(preservedHeaders, provider.NameHeaders...)
			preservedHeaders = append(preservedHeaders, provider.EmailHeaders...)
		}
	}

	return preservedHeaders
}

func WithPreserveOAuthHeaders(handler http.Handler, oauthConfig osinv1.OAuthConfig) http.Handler {
	headers := append(preservedHeaders(&oauthConfig), authzHeader)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range headers {
			if vv, ok := r.Header[header]; ok {
				headerCopy := headerCopyPrefix + header
				r.Header[headerCopy] = vv // capture the values before they are deleted
			}
		}

		handler.ServeHTTP(w, r)
	})
}

func WithRestoreOAuthHeaders(handler http.Handler, oauthConfig osinv1.OAuthConfig) http.Handler {
	headers := append(preservedHeaders(&oauthConfig), authzHeader)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range headers {
			headerCopy := headerCopyPrefix + header
			if vv, ok := r.Header[headerCopy]; ok {
				r.Header[header] = vv // add them back afterwards for use in OAuth flows
				delete(r.Header, headerCopy)
			}
		}

		handler.ServeHTTP(w, r)
	})
}
