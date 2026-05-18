package api_test

import (
	"testing"

	"github.com/stretchr/testify/suite"

	testutiltesting "github.com/ory-corp/talos/internal/testutil/testserver"
)

// HTTP API paths
const (
	pathKeys = "/v2alpha1/admin/issuedApiKeys"
)

// HTTP headers
const (
	contentTypeJSON = "application/json"
)

// APIKeyE2ETestSuite contains end-to-end tests for the API key service
type APIKeyE2ETestSuite struct {
	suite.Suite

	testServer *testutiltesting.TestServer
}

func TestAPIKeyE2E(t *testing.T) {
	suite.Run(t, new(APIKeyE2ETestSuite))
}

func (s *APIKeyE2ETestSuite) SetupSuite() {
	s.testServer = testutiltesting.NewTestServer(s.T())
}

func (s *APIKeyE2ETestSuite) TearDownSuite() {
	s.testServer.Close()
}

func (s *APIKeyE2ETestSuite) SetupTest() {
	// Reset the failure-event rate limiter so each test function starts with a
	// clean slate. Without this, high-volume failure verifications in earlier
	// tests exhaust the per-NID limit and silence failure events in later tests.
	s.testServer.ResetFailureEventLimiter()
}

// reviewed - @aeneasr - 2026-03-27
