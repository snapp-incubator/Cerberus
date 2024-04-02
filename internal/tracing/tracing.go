package tracing

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/contrib/propagators/autoprop"

)

const (
	CerberusTracerName  = "cerberus"
	ServiceName         = "cerberus"
	HTTPTracingProvider = "http-tracing-provider"
	GRPCTracingProvider = "grpc-tracing-provider"
	TimeFormat          = time.RFC3339Nano
)

var cerberusTracer trace.Tracer
var tp *tracesdk.TracerProvider

func init() {
	cerberusTracer = otel.Tracer(CerberusTracerName)
}

func SetTracingProvider(provider string, samplingRatio float64, timeout float64) (err error) {
    var exporter *otlptrace.Exporter

    switch provider {
    case HTTPTracingProvider:
        exporter, err = otlptracehttp.New(context.Background(),
            otlptracehttp.WithTimeout(time.Second*time.Duration(timeout)),
        )
    case GRPCTracingProvider:
        exporter, err = otlptracegrpc.New(context.Background(),
            otlptracegrpc.WithTimeout(time.Second*time.Duration(timeout)),
        )
    default:
        err = fmt.Errorf("invalid-tracing-provider")
    }

    if err != nil {
        return err
    }

    tp = tracesdk.NewTracerProvider(
        tracesdk.WithBatcher(exporter),
        tracesdk.WithSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(samplingRatio))),
        tracesdk.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceNameKey.String(ServiceName),
        )),
    )
    cerberusTracer = tp.Tracer(CerberusTracerName)

    otel.SetTextMapPropagator(autoprop.NewTextMapPropagator())

    return nil
}


func StartSpan(ctx context.Context, spanName string, extraAttrs ...attribute.KeyValue) (context.Context, trace.Span) {
	newCtx, span := cerberusTracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindServer),
	)
	extraAttrs = append(extraAttrs,
		attribute.String("start-time", time.Now().Format(TimeFormat)),
	)
	span.SetAttributes(extraAttrs...)
	return newCtx, span
}

func EndSpan(span trace.Span, start_time time.Time, extraAttrs ...attribute.KeyValue) {
	extraAttrs = append(extraAttrs,
		attribute.String("end-time", time.Now().Format(TimeFormat)),
		attribute.Float64("duration_seconds", time.Since(start_time).Seconds()),
	)
	span.SetAttributes(extraAttrs...)
	span.End()
}

func ReadParentSpanFromRequest(ctx context.Context, req http.Request) context.Context {
	return otel.GetTextMapPropagator().Extract(
		ctx, propagation.HeaderCarrier(req.Header),
	)
}

func Tracer() *trace.Tracer {
	return &cerberusTracer
}

func Shutdown(ctx context.Context) error {
	return tp.Shutdown(ctx)
}
