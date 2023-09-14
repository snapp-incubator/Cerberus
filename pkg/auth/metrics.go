package auth

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	CerberusReasonLabel      = "cerberus_reason"
	CheckRequestVersionLabel = "check_request_version"
	ObjectKindLabel          = "kind"

	MetricsKindSecret                  = "secret"
	MetricsKindWebservice              = "webservice"
	MetricsKindAccessToken             = "accesstoken"
	MetricsKindWebserviceAccessBinding = "webserviceaccessbinding"

	MetricsCheckRequestVersion2 = "v2"
	MetricsCheckRequestVersion3 = "v3"
)

var (
	DurationBuckets      = []float64{0.00005, .0001, .0005, .001, .002, .005, .01, .05, .1, 1, 2.5, 5, 10}
	SmallDurationBuckets = []float64{0.0000001, 0.000001, 0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.001, 0.01, 0.05, 0.1}

	reqCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "check_request_count",
			Help: "CheckRequest count",
		},
		[]string{CerberusReasonLabel, CheckRequestVersionLabel},
	)

	reqLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "check_request_duration_seconds",
			Help:    "CheckRequest durations (response times)",
			Buckets: DurationBuckets,
		},
		[]string{CerberusReasonLabel},
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
	)
}

func ReasonLabel(reason CerberusReason) prometheus.Labels {
	labels := prometheus.Labels{}
	labels[CerberusReasonLabel] = string(reason)
	return labels
}

func KindLabel(kind string) prometheus.Labels {
	labels := prometheus.Labels{}
	labels[ObjectKindLabel] = kind
	return labels
}
