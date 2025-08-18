package auth

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	CerberusReasonLabel         = "cerberus_reason"
	CheckRequestVersionLabel    = "check_request_version"
	HasUpstreamAuth             = "upstream_auth_enabled"
	ObjectKindLabel             = "kind"
	WithDownstreamDeadlineLabel = "with_downstream_deadline"
	WebserviceLabel             = "webservice"

	MetricsKindSecret                  = "secret"
	MetricsKindWebservice              = "webservice"
	MetricsKindAccessToken             = "accesstoken"
	MetricsKindWebserviceAccessBinding = "webserviceaccessbinding"
	StatusCode                         = "status_code"

	MetricsCheckRequestVersion2 = "v2"
	MetricsCheckRequestVersion3 = "v3"
)

var (
	DurationBuckets      = []float64{0.000005, 0.00001, 0.000015, 0.00003, 0.00004, 0.00005, 0.000075, 0.0001, 0.000125, 0.00015, 0.000175, 0.0002, 0.00025, .0005, .001, .002, .003, .004, .005, .006, .007, .008, .009, .01, .02, .05, .1, 1, 2.5, 5}
	SmallDurationBuckets = []float64{0.0000001, 0.000001, 0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.001, 0.01, 0.05, 0.1}

	reqCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "check_request_count",
			Help: "CheckRequest count",
		},
		[]string{CerberusReasonLabel, CheckRequestVersionLabel, HasUpstreamAuth, WebserviceLabel},
	)

	reqLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "check_request_duration_seconds",
			Help:    "CheckRequest durations (response times)",
			Buckets: DurationBuckets,
		},
		[]string{CerberusReasonLabel, CheckRequestVersionLabel, HasUpstreamAuth},
	)

	cacheUpdateCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_updates_count",
			Help: "CacheUpdate call count",
		},
	)

	cacheUpdateLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cache_update_duration_seconds",
			Help:    "CacheUpdate duration",
			Buckets: DurationBuckets,
		},
	)

	cacheWriteLockWaitingTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cache_write_lock_waiting_duration_seconds",
			Help:    "Time that CacheUpdate waits to accuire write lock",
			Buckets: SmallDurationBuckets,
		},
	)

	cacheWriteTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cache_write_duration_seconds",
			Help:    "Writing time lock duration",
			Buckets: SmallDurationBuckets,
		},
	)

	cacheReaders = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cache_read_locks",
			Help: "Number of active read_lock on the cache",
		},
	)

	accessCacheEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "access_cache_entries",
			Help: "Number of entries in Authenticator AccessCache",
		},
	)

	webserviceCacheEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "webservice_cache_entries",
			Help: "Number of entries in Authenticator ServicesCache",
		},
	)

	fetchObjectListLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fetch_object_list_latency",
			Help:    "latency of requsts to kubernetes API server",
			Buckets: DurationBuckets,
		},
		[]string{ObjectKindLabel},
	)

	serviceUpstreamAuthCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upstream_auth_calls_total",
			Help: "The total number of checkServiceUpstreamAuth function calls",
		},
		[]string{WithDownstreamDeadlineLabel},
	)

	upstreamAuthRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "upstream_auth_request_duration_seconds",
			Help:    "Duration of the UpstreamAuth Requests in seconds",
			Buckets: DurationBuckets,
		},
		[]string{StatusCode, WithDownstreamDeadlineLabel},
	)

	upstreamAuthFailedRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upstream_auth_failed_requests_total",
			Help: "Total number of failed UpstreamAuth requests",
		},
		[]string{WithDownstreamDeadlineLabel},
	)

	upstreamAuthEmptyTokens = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "upstream_auth_empty_tokens_total",
			Help: "Total number of UpstreamAuth requests that token were empty",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		reqCount,
		reqLatency,
		cacheUpdateCount,
		cacheUpdateLatency,
		cacheWriteLockWaitingTime,
		cacheWriteTime,
		cacheReaders,
		accessCacheEntries,
		webserviceCacheEntries,
		fetchObjectListLatency,
		serviceUpstreamAuthCalls,
		upstreamAuthRequestDuration,
		upstreamAuthFailedRequests,
	)
}

func AddReasonLabel(labels prometheus.Labels, reason CerberusReason) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	labels[CerberusReasonLabel] = string(reason)
	return labels
}

func AddKindLabel(labels prometheus.Labels, kind string) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	labels[ObjectKindLabel] = kind
	return labels
}

func AddStatusLabel(labels prometheus.Labels, status int) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	labels[StatusCode] = strconv.Itoa(status)
	return labels
}

func AddUpstreamAuthLabel(labels prometheus.Labels, hasUpstreamAuth string) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	labels[HasUpstreamAuth] = hasUpstreamAuth
	return labels
}

func AddWithDownstreamDeadlineLabel(labels prometheus.Labels, hasDeadline bool) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	if hasDeadline {
		labels[WithDownstreamDeadlineLabel] = "true"
	} else {
		labels[WithDownstreamDeadlineLabel] = "false"
	}
	return labels
}

func AddWebserviceLabel(labels prometheus.Labels, wsvc string) prometheus.Labels {
	if labels == nil {
		labels = prometheus.Labels{}
	}
	labels[WebserviceLabel] = wsvc
	return labels
}
