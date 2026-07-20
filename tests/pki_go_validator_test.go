package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClassifyConcreteErrors(t *testing.T) {
	certificate := &x509.Certificate{}
	tests := []struct {
		name   string
		err    error
		status string
		reason string
	}{
		{"hostname", x509.HostnameError{Certificate: certificate, Host: "wrong.example"}, statusReject, "identity_mismatch"},
		{"unknown authority", x509.UnknownAuthorityError{Cert: certificate}, statusReject, "untrusted_or_incomplete_path"},
		{"expiration", x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired}, statusReject, "validity_failure"},
		{"name constraints", x509.CertificateInvalidError{Cert: certificate, Reason: x509.CANotAuthorizedForThisName}, statusReject, "name_constraints_violation"},
		{"path length", x509.CertificateInvalidError{Cert: certificate, Reason: x509.TooManyIntermediates}, statusReject, "path_length_violation"},
		{"eku", x509.CertificateInvalidError{Cert: certificate, Reason: x509.IncompatibleUsage}, statusReject, "extended_key_usage_failure"},
		{"constraint violation", x509.ConstraintViolationError{}, statusReject, "key_usage_failure"},
		{"insecure algorithm", x509.InsecureAlgorithmError(x509.SHA1WithRSA), statusReject, "signature_algorithm_invalid"},
		{"unknown critical extension", x509.UnhandledCriticalExtension{}, statusReject, "unknown_critical_extension"},
		{"resource limit", x509.CertificateInvalidError{Cert: certificate, Reason: x509.TooManyConstraints}, statusToolFailure, "resource_limit"},
		{"system roots", x509.SystemRootsError{Err: errors.New("roots unavailable")}, statusToolFailure, "oracle_failure"},
		{"unknown invalid reason", x509.CertificateInvalidError{Cert: certificate, Reason: x509.InvalidReason(999)}, statusReject, "unclassified_rejection"},
		{"unknown error", errors.New("new validator error"), statusReject, "unclassified_rejection"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyError(test.err)
			if got.status != test.status || got.reason != test.reason {
				t.Fatalf("classifyError() = %#v, want status=%q reason=%q", got, test.status, test.reason)
			}
		})
	}
}

func TestClassifyParseErrors(t *testing.T) {
	tests := []struct {
		message string
		reason  string
	}{
		{"x509: certificate contains duplicate extension with OID 1.2.3", "duplicate_extension"},
		{"x509: inner and outer signature algorithm identifiers don't match", "signature_algorithm_invalid"},
		{"x509: Ed25519 key encoded with illegal parameters", "issuer_key_or_spki_invalid"},
		{"x509: malformed certificate", "malformed_der"},
		{"brand new parser diagnostic", "unclassified_rejection"},
	}
	for _, test := range tests {
		if got := classifyParseError(errors.New(test.message)); got != test.reason {
			t.Errorf("classifyParseError(%q) = %q, want %q", test.message, got, test.reason)
		}
	}
}

func TestValidateAcceptedChainAndStableJSON(t *testing.T) {
	result, err := validate(config{
		rootPaths:         pathList{"vectors/pki/root.crt"},
		intermediatePaths: pathList{"vectors/pki/intermediate.crt"},
		leafPath:          "vectors/pki/valid-leaf.crt",
		validationTime:    time.Unix(1784332800, 0).UTC(),
		dnsName:           "api.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Status != statusAccept || result.Reason != "accepted" {
		t.Fatalf("unexpected accepted observation: %#v", result)
	}

	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(result); err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if err := json.Unmarshal(encoded.Bytes(), &shape); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"validator", "accepted", "status", "reason", "diagnostic"} {
		if _, ok := shape[field]; !ok {
			t.Errorf("JSON omitted required field %q: %s", field, encoded.String())
		}
	}
}

func TestValidateMalformedCertificate(t *testing.T) {
	result, err := validate(config{
		rootPaths:      pathList{"vectors/pki/root.crt"},
		leafPath:       "vectors/pki/malformed-truncated.crt",
		validationTime: time.Unix(1784332800, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted || result.Status != statusReject || result.Reason != "malformed_der" {
		t.Fatalf("unexpected malformed observation: %#v", result)
	}
}

func TestDiagnosticBoundIsUTF8Safe(t *testing.T) {
	message := strings.Repeat("é", maxDiagnosticSize)
	got := boundedDiagnostic(message)
	if len(got) > maxDiagnosticSize {
		t.Fatalf("bounded diagnostic has %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("bounded diagnostic lacks truncation suffix: %q", got)
	}
}
