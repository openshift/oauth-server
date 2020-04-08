package metrics

import (
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
	authPasswordTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "password_total",
			Help:      "Counts total password authentication attempts",
		}, []string{},
	)
	authFormCounter = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "form_password_count",
			Help:      "Counts form password authentication attempts",
		}, []string{},
	)
	authFormCounterResult = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "form_password_count_result",
			Help:      "Counts form password authentication attempts by result",
		}, []string{"result"},
	)
	authBasicCounter = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "basic_password_count",
			Help:      "Counts basic password authentication attempts",
		}, []string{},
	)
	authBasicCounterResult = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem: authSubsystem,
			Name:      "basic_password_count_result",
			Help:      "Counts basic password authentication attempts by result",
		}, []string{"result"},
	)
)

func init() {
	legacyregistry.MustRegister(authPasswordTotal)
	legacyregistry.MustRegister(authFormCounter)
	legacyregistry.MustRegister(authFormCounterResult)
	legacyregistry.MustRegister(authBasicCounter)
	legacyregistry.MustRegister(authBasicCounterResult)
}

func RecordBasicPasswordAuth(result string) {
	authPasswordTotal.WithLabelValues().Inc()
	authBasicCounter.WithLabelValues().Inc()
	authBasicCounterResult.WithLabelValues(result).Inc()
}

func RecordFormPasswordAuth(result string) {
	authPasswordTotal.WithLabelValues().Inc()
	authFormCounter.WithLabelValues().Inc()
	authFormCounterResult.WithLabelValues(result).Inc()
}
