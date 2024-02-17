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
	JaegerTracing      = "jaeger"
)

var cerberusTracer trace.Tracer

func init() {
	cerberusTracer = otel.Tracer(CerberusTracerName)
}

func SetTracingProvider(provider string) error {
	if provider == JaegerTracing {
		exporter, err := jaeger.New(jaeger.WithAgentEndpoint())
		if err != nil {
			return nil, err
		}
		tp := tracesdk.NewTracerProvider(
			tracesdk.WithBatcher(exporter),
			tracesdk.WithSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(samplerRatio))),
			// Record information about this application in a Resource.
			tracesdk.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(serviceName),
			)),
		)
		return tp, nil

	}
	return fmt.Errorf("invalid-tracing-provider")
}

func StartSpan(ctx context.Context, spanName string) (context.Context, trace.Span) {
	return cerberusTracer.Start(ctx, spanName)
}

func Tracer() *trace.Tracer {
	return &cerberusTracer
}
