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
)

func init() {
	legacyregistry.MustRegister(authPasswordTotal)
	legacyregistry.MustRegister(authFormCounter)
	legacyregistry.MustRegister(authFormCounterResult)
	legacyregistry.MustRegister(authBasicCounter)
	legacyregistry.MustRegister(authBasicCounterResult)

	for _, resultLabel := range []string{SuccessResult, FailResult, ErrorResult} {
		authBasicCounterResult.WithLabelValues(resultLabel)
		authFormCounterResult.WithLabelValues(resultLabel)
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
