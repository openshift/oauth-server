package oauthserver

import (
	"net/http"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

// newRoundTripper creates an outbound IdP round tripper with the configured
// static IdP TLS material and, when present, dynamically reloaded proxy CA
// content. The library-go round tripper uses the standard proxy environment
// variables by default.
func newRoundTripper(proxyCAContent dynamiccertificates.CAContentProvider, caFile, certFile, keyFile string) (http.RoundTripper, error) {
	var opts []httptransport.Option
	if len(caFile) > 0 {
		opts = append(opts, httptransport.WithCAFile("identity provider CA", caFile))
	}
	if len(certFile) > 0 || len(keyFile) > 0 {
		opts = append(opts, httptransport.WithClientCertificateFile(certFile, keyFile))
	}
	if proxyCAContent != nil {
		opts = append(opts, httptransport.WithCAContentProvider(proxyCAContent))
	}

	return httptransport.NewRoundTripper(opts...)
}
