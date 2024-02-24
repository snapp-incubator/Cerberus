package settings

import "github.com/ilyakaznacheev/cleanenv"

type Settings struct {
	AuthServerAddress string `yaml:"bindAddress" env:"BIND_ADDRESS" env-default:":8082" env-description:"The address the authorization service binds to."`
	MetricsAddress    string `yaml:"metricsBindAddress" env:"METRICS_BIND_ADDRESS" env-default:":8080" env-description:"The address the metric endpoint binds to."`
	ProbeAddress      string `yaml:"healthProbeBindAddress" env:"PROBE_BIND_ADDRESS" env-default:":8081" env-description:"The address the probe endpoint binds to."`

	TLS struct {
		CertPath string `yaml:"certPath" env:"AUTH_SERVER_TLS_CERT_PATH" env-default:"" env-description:"grpc Authentication server TLS certificate file path"`
		KeyPath  string `yaml:"keyPath" env:"AUTH_SERVER_TLS_KEY_PATH" env-default:"" env-description:"grpc Authentication server TLS Key file path"`
		CaPath   string `yaml:"caPath" env:"AUTH_SERVER_TLS_CA_PATH" env-default:"" env-description:"grpc Authentication server TLS CA file path"`
	} `yaml:"tls"`

	LeaderElection struct {
		Enabled bool   `yaml:"enabled" env:"LEADER_ELECTION_ENABLED" env-default:"false" env-description:"Enable leader election for controller manager."`
		ID      string `yaml:"id" env:"LEADER_ELECTION_ID" env-default:"f5d1781e.snappcloud.io" env-description:"ID determines the name of the resource that leader election will use for holding the leader lock."`
	} `yaml:"leaderElection"`

	Tracing struct {
		Enabled       bool    `yaml:"enabled" env:"ENABLE_TRACING" env-default:"false" env-description:"Enable OpenTelemetry tracing."`
		Provider      string  `yaml:"provider" env:"TRACING_PROVIDER" env-default:"jaeger" env-description:"only jaeger is available now"`
		SamplingRatio float64 `yaml:"samplingRatio" env:"TRACING_SAMPLING_RATIO" env-default:"0.001" env-description:"sets sampling portion of requests"`
		Timeout       float64 `yaml:"timeout" env:"TRACING_TIMEOUT_SECONDS" env-default:"1" env-description:"sets tracing timeout in seconds"`
	} `yaml:"tracing"`
}

func GetSettings() (st Settings, err error) {
	err = cleanenv.ReadEnv(&st)
	return
}
