package oauth_server

import (
	"errors"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"

	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/library-go/pkg/config/helpers"
	"github.com/openshift/library-go/pkg/config/serving"
	"github.com/openshift/oauth-server/pkg/oauthserver"

	// for metrics
	_ "github.com/openshift/library-go/pkg/controller/metrics"
)

func RunOsinServer(osinConfig *osinv1.OsinServerConfig, stopCh <-chan struct{}) error {
	if osinConfig == nil {
		return errors.New("osin server requires non-empty oauthConfig")
	}

	oauthServerConfig, err := newOAuthServerConfig(osinConfig)
	if err != nil {
		return err
	}

	oauthServer, err := oauthServerConfig.Complete().New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	return oauthServer.GenericAPIServer.PrepareRun().Run(stopCh)
}

func newOAuthServerConfig(osinConfig *osinv1.OsinServerConfig) (*oauthserver.OAuthServerConfig, error) {
	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, corev1.SchemeGroupVersion)
	genericConfig := genericapiserver.NewRecommendedConfig(serializer.NewCodecFactory(scheme))

	servingOptions, err := serving.ToServingOptions(osinConfig.ServingInfo)
	if err != nil {
		return nil, err
	}
	if err := servingOptions.ApplyTo(&genericConfig.Config.SecureServing, &genericConfig.Config.LoopbackClientConfig); err != nil {
		return nil, err
	}
	// the oauth-server must only run in http1 to avoid http2 connection re-use problems when improperly re-using a wildcard certificate
	genericConfig.Config.SecureServing.HTTP1Only = true

	authenticationOptions := genericapiserveroptions.NewDelegatingAuthenticationOptions()
	authenticationOptions.ClientCert.ClientCA = osinConfig.ServingInfo.ClientCA
	authenticationOptions.RemoteKubeConfigFile = osinConfig.KubeClientConfig.KubeConfig
	if err := authenticationOptions.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.OpenAPIConfig); err != nil {
		return nil, err
	}

	authorizationOptions := genericapiserveroptions.NewDelegatingAuthorizationOptions().
		// TODO better formalize / generate this list as trailing * matters
		WithAlwaysAllowPaths( // The five sections are:
			"/healthz", "/healthz/", // 1. Health checks (root, no wildcard)
			"/oauth/*",           // 2. OAuth (wildcard)
			"/login", "/login/*", // 3. Login (both root and wildcard)
			"/logout", "/logout/", // 4. Logout (root, no wildcard)
			"/oauth2callback/*", // 5. OAuth callbacks (wildcard)
		).
		WithAlwaysAllowGroups(user.SystemPrivilegedGroup)
	authorizationOptions.RemoteKubeConfigFile = osinConfig.KubeClientConfig.KubeConfig
	if err := authorizationOptions.ApplyTo(&genericConfig.Authorization); err != nil {
		return nil, err
	}

	// TODO You need real overrides for rate limiting
	kubeClientConfig, err := helpers.GetKubeConfigOrInClusterConfig(osinConfig.KubeClientConfig.KubeConfig, osinConfig.KubeClientConfig.ConnectionOverrides)
	if err != nil {
		return nil, err
	}

	oauthServerConfig, err := oauthserver.NewOAuthServerConfig(osinConfig.OAuthConfig, kubeClientConfig, genericConfig)
	if err != nil {
		return nil, err
	}

	// TODO you probably want to set this
	oauthServerConfig.GenericConfig.CorsAllowedOriginList = osinConfig.CORSAllowedOrigins
	//oauthServerConfig.GenericConfig.AuditBackend = genericConfig.AuditBackend
	//oauthServerConfig.GenericConfig.AuditPolicyChecker = genericConfig.AuditPolicyChecker

	return oauthServerConfig, nil
}
