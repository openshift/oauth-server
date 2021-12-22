package metrics

import (
	configv1 "github.com/openshift/api/config/v1"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

const (
	authSubsystem = "openshift_auth"
)

const (
	SuccessResult = "success"
	FailResult    = "failure"
	ErrorResult   = "error"
)

var (
	authPasswordTotal = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "password_total",
			Help:      "Counts total password authentication attempts",
		},
	)
	authFormCounter = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "form_password_count",
			Help:      "Counts form password authentication attempts",
		},
	)
	authFormCounterResult = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "form_password_count_result",
			Help:      "Counts form password authentication attempts by result",
		}, []string{"result"},
	)
	authBasicCounter = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "basic_password_count",
			Help:      "Counts basic password authentication attempts",
		},
	)
	authBasicCounterResult = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "basic_password_count_result",
			Help:      "Counts basic password authentication attempts by result",
		}, []string{"result"},
	)
	X509MissingSANCounter = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "x509_missing_san_total",
			Help: "Counts the number of requests to servers missing SAN extension " +
				"in their serving certificate OR the number of connection failures " +
				"due to the lack of x509 certificate SAN extension missing " +
				"(either/or, based on the runtime environment)",
		}, []string{"provider"},
	)
)

func init() {
	legacyregistry.MustRegister(authPasswordTotal)
	legacyregistry.MustRegister(authFormCounter)
	legacyregistry.MustRegister(authFormCounterResult)
	legacyregistry.MustRegister(authBasicCounter)
	legacyregistry.MustRegister(authBasicCounterResult)
	legacyregistry.MustRegister(X509MissingSANCounter)

	for _, resultLabel := range []string{SuccessResult, FailResult, ErrorResult} {
		authBasicCounterResult.WithLabelValues(resultLabel)
		authFormCounterResult.WithLabelValues(resultLabel)
	}

	for _, provider := range [...]configv1.IdentityProviderType{
		configv1.IdentityProviderTypeBasicAuth,
		configv1.IdentityProviderTypeGitHub,
		configv1.IdentityProviderTypeGitLab,
		configv1.IdentityProviderTypeGoogle,
		configv1.IdentityProviderTypeKeystone,
		configv1.IdentityProviderTypeLDAP,
		configv1.IdentityProviderTypeOpenID,
	} {
		X509MissingSANCounter.WithLabelValues(string(provider))
	}
}

func RecordBasicPasswordAuth(result string) {
	authPasswordTotal.Inc()
	authBasicCounter.Inc()
	authBasicCounterResult.WithLabelValues(result).Inc()
}

func RecordFormPasswordAuth(result string) {
	authPasswordTotal.Inc()
	authFormCounter.Inc()
	authFormCounterResult.WithLabelValues(result).Inc()
}
