package settings

import "flag"

func (s Settings) BindFlags(fs *flag.FlagSet) {
	flag.StringVar(&s.MetricsAddress, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&s.ProbeAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&s.AuthServerAddress, "address", ":8082", "The address the authorization service binds to.")

	flag.StringVar(&s.TLS.CertPath, "tls-cert-path", "", "grpc Authentication server TLS certificate")
	flag.StringVar(&s.TLS.KeyPath, "tls-key-path", "", "grpc Authentication server TLS key")
	flag.StringVar(&s.TLS.CaPath, "tls-ca-path", "", "grpc Authentication server CA certificate")

	flag.BoolVar(&s.Tracing.Enabled, "enable-tracing", false,
		"Enable OpenTelemetry Tracing. "+
			"After enabling this you should add --tracing-provider")
	flag.StringVar(&s.Tracing.Provider, "tracing-provider", "jaeger",
		"Tracing provider, for now only 'jaeger'. "+
			"You should also set OTEL_EXPORTER_JAEGER_AGENT_HOST and OTEL_EXPORTER_JAEGER_AGENT_PORT.")
	flag.Float64Var(&s.Tracing.SamplingRatio, "tracing-sampling-ratio", 0.001,
		"Tracing sampling ration sets sampling portion of requests")
	flag.Float64Var(&s.Tracing.Timeout, "tracing-sampling-ratio", 1,
		"sets tracing timeout in seconds")

	flag.BoolVar(&s.LeaderElection.Enabled, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
}
