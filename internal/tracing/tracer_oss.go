//go:build !commercial

package tracing

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"

	"github.com/ory/talos/internal/config"
)

// InitTracer configures the global OpenTelemetry TracerProvider from the
// tracing.* config block.
//
// When tracing is disabled (the default) it returns (nil, nil) so the caller
// skips tracer shutdown. When enabled with exporter "otlp", it dials the gRPC
// OTLP collector at tracing.endpoint and installs a batching TracerProvider
// with a TraceIDRatioBased sampler. The gRPC exporter dials lazily, so
// construction succeeds even before the collector (Alloy :4317) is reachable.
//
// The returned *sdktrace.TracerProvider is non-nil only when tracing is active;
// the caller (cmd/serve_shared.go) registers its Shutdown on process exit.
func InitTracer(ctx context.Context, p config.ProviderInterface) (*sdktrace.TracerProvider, error) {
	if !p.Bool(ctx, config.KeyTracingEnabled) {
		return nil, nil
	}

	exporter := p.String(ctx, config.KeyTracingExporter)
	if exporter != "otlp" {
		return nil, fmt.Errorf("tracing.exporter %q is not supported (oss supports \"otlp\")", exporter)
	}

	endpoint := strings.TrimSpace(p.String(ctx, config.KeyTracingEndpoint))
	if endpoint == "" {
		return nil, fmt.Errorf("tracing.endpoint is required when tracing.exporter is otlp")
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("create otlp/gRPC trace exporter for %s: %w", endpoint, err)
	}

	serviceName := p.String(ctx, config.KeyTracingServiceName)
	if serviceName == "" {
		serviceName = "talos"
	}
	environment := p.String(ctx, config.KeyTracingEnvironment)
	if environment == "" {
		environment = "development"
	}
	ratio := p.Float64(ctx, config.KeyTracingSampleRate)
	if ratio <= 0 {
		ratio = 0.001
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironmentName(environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create trace resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)

	return tp, nil
}
