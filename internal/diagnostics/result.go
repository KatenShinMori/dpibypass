package diagnostics

import (
	"fmt"
	"time"
)

// Outcome classifies the final result of a diagnostic connectivity check.
type Outcome int

const (
	// OutcomeSuccess indicates both transport and valid HTTP response succeeded.
	OutcomeSuccess Outcome = iota

	// OutcomeHTTPRestricted indicates HTTP 403 or 451 was observed (possible restriction indicator).
	OutcomeHTTPRestricted

	// OutcomeInvalidConfig indicates invalid domain name, port, or configuration parameters.
	OutcomeInvalidConfig

	// OutcomeDNSFailure indicates domain name resolution failed.
	OutcomeDNSFailure

	// OutcomeTCPConnectionFailure indicates TCP connection establishment failed (refused, unreachable).
	OutcomeTCPConnectionFailure

	// OutcomeTimeout indicates a deadline expired during DNS, TCP dial, TLS handshake, or HTTP probe.
	OutcomeTimeout

	// OutcomeConnectionReset indicates connection was reset by peer during or after handshake.
	OutcomeConnectionReset

	// OutcomeTLSHandshakeFailure indicates a TLS protocol error, alert, or abnormal handshake termination.
	OutcomeTLSHandshakeFailure

	// OutcomeCertVerificationFailure indicates x509 certificate hostname mismatch, untrusted authority, or expiry.
	OutcomeCertVerificationFailure

	// OutcomeHTTPResponseInvalid indicates server returned malformed non-HTTP data or headers exceeded 16 KiB.
	OutcomeHTTPResponseInvalid

	// OutcomeUnsupportedStrategy indicates the selected strategy cannot be applied to this transport.
	OutcomeUnsupportedStrategy
)

func (o Outcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "SUCCESS"
	case OutcomeHTTPRestricted:
		return "HTTP_RESTRICTED"
	case OutcomeInvalidConfig:
		return "INVALID_CONFIG"
	case OutcomeDNSFailure:
		return "DNS_FAILURE"
	case OutcomeTCPConnectionFailure:
		return "TCP_CONNECT_FAILURE"
	case OutcomeTimeout:
		return "TIMEOUT"
	case OutcomeConnectionReset:
		return "CONNECTION_RESET"
	case OutcomeTLSHandshakeFailure:
		return "TLS_HANDSHAKE_FAILURE"
	case OutcomeCertVerificationFailure:
		return "CERT_VERIFICATION_FAILURE"
	case OutcomeHTTPResponseInvalid:
		return "HTTP_RESPONSE_INVALID"
	case OutcomeUnsupportedStrategy:
		return "UNSUPPORTED_STRATEGY"
	default:
		return fmt.Sprintf("OUTCOME_%d", int(o))
	}
}

// CheckResult contains structured metrics and outcome from a single diagnostic probe.
type CheckResult struct {
	Domain          string
	Port            int
	StrategyName    string
	StrategyApplied bool
	ResolvedIPs     []string
	SelectedIP      string
	Outcome         Outcome
	FailureReason   string
	HTTPStatusCode  int
	DNSDuration     time.Duration
	TCPDuration     time.Duration
	TLSDuration     time.Duration
	HTTPDuration    time.Duration
	TotalDuration   time.Duration
}

// IsSuccess returns true if transport succeeded and server returned a valid non-restricted HTTP status.
func (r CheckResult) IsSuccess() bool {
	return r.Outcome == OutcomeSuccess
}
