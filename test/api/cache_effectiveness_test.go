// This file intentionally left empty.
//
// The flaky E2E cache test that was here relied on prometheus.DefaultGatherer,
// which produced non-deterministic results when other tests ran in parallel.
//
// Cache hit/miss metrics are now unit-tested deterministically in
// internal/metrics/collector_test.go using a dedicated prometheus.NewRegistry()
// per test.
package api_test
