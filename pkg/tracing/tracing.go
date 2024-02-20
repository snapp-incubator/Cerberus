package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	CerberusTracerName = "cerberus"
	ServiceName        = "cerberus"
	JaegerTracing      = "jaeger"
)

var cerberusTracer trace.Tracer
var tp *tracesdk.TracerProvider

func init() {
	cerberusTracer = otel.Tracer(CerberusTracerName)
}

func SetTracingProvider(provider string, samplingRation float64) error {
	if provider == JaegerTracing {
		exporter, err := jaeger.New(jaeger.WithAgentEndpoint())
		if err != nil {
			return err
		}
		tp = tracesdk.NewTracerProvider(
			tracesdk.WithBatcher(exporter),
			tracesdk.WithSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(samplingRation))),
			tracesdk.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(ServiceName),
			)),
		)
		cerberusTracer = tp.Tracer(CerberusTracerName)
		return nil

	}
	return fmt.Errorf("invalid-tracing-provider")
}

func StartSpan(ctx context.Context, spanName string) (context.Context, trace.Span) {
	return cerberusTracer.Start(ctx, spanName)
}

func Tracer() *trace.Tracer {
	return &cerberusTracer
}

func Shutdown(ctx context.Context) error {
	return tp.Shutdown(ctx)
}
