// pki_go_validator is an out-of-process certificate validation oracle backed
// by the Go standard library's crypto/x509 package.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	validatorName     = "go-crypto-x509"
	maxDiagnosticSize = 512
	maxPEMFileSize    = 16 << 20
)

type pathList []string

func (paths *pathList) String() string {
	return strings.Join(*paths, ",")
}

func (paths *pathList) Set(path string) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	*paths = append(*paths, path)
	return nil
}

type config struct {
	rootPaths         pathList
	intermediatePaths pathList
	leafPath          string
	validationTime    time.Time
	dnsName           string
}

type decision struct {
	Validator  string `json:"validator"`
	Accepted   bool   `json:"accepted"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Diagnostic string `json:"diagnostic"`
}

const (
	statusAccept      = "accept"
	statusReject      = "reject"
	statusToolFailure = "tool_failure"
)

type classifiedError struct {
	status string
	reason string
}

type certificateParseError struct {
	reason string
	err    error
}

func (e *certificateParseError) Error() string { return e.err.Error() }
func (e *certificateParseError) Unwrap() error { return e.err }

type certificateFile struct {
	path         string
	contents     []byte
	contentIssue string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "pki_go_validator: %v\n", err)
		return 2
	}

	result, err := validate(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "pki_go_validator: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "pki_go_validator: write decision: %v\n", err)
		return 1
	}
	return 0
}

func parseFlags(args []string, stderr io.Writer) (config, error) {
	var cfg config
	var validationTime string

	flags := flag.NewFlagSet("pki_go_validator", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Var(&cfg.rootPaths, "root", "PEM trust-anchor file (repeatable)")
	flags.Var(&cfg.intermediatePaths, "intermediate", "PEM intermediate-certificate file (repeatable)")
	flags.StringVar(&cfg.leafPath, "leaf", "", "PEM leaf-certificate file")
	flags.StringVar(&validationTime, "time", "", "validation time as Unix seconds")
	flags.StringVar(&cfg.dnsName, "dns-name", "", "optional DNS identity to verify")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s --root PATH [--root PATH ...] [--intermediate PATH ...] --leaf PATH --time UNIX [--dns-name NAME]\n", flags.Name())
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	if len(cfg.rootPaths) == 0 {
		return config{}, errors.New("at least one --root is required")
	}
	if cfg.leafPath == "" {
		return config{}, errors.New("--leaf is required")
	}
	if validationTime == "" {
		return config{}, errors.New("--time is required")
	}

	seconds, err := strconv.ParseInt(validationTime, 10, 64)
	if err != nil {
		return config{}, fmt.Errorf("invalid --time %q: expected Unix seconds", validationTime)
	}
	cfg.validationTime = time.Unix(seconds, 0).UTC()
	return cfg, nil
}

func validate(cfg config) (decision, error) {
	rootFiles, err := readCertificateFiles(cfg.rootPaths)
	if err != nil {
		return decision{}, err
	}
	intermediateFiles, err := readCertificateFiles(cfg.intermediatePaths)
	if err != nil {
		return decision{}, err
	}
	leafFile, err := readCertificateFile(cfg.leafPath)
	if err != nil {
		return decision{}, err
	}

	roots := x509.NewCertPool()
	for _, file := range rootFiles {
		certificates, err := parsePEMCertificates(file)
		if err != nil {
			return rejected(err), nil
		}
		for _, certificate := range certificates {
			roots.AddCert(certificate)
		}
	}

	intermediates := x509.NewCertPool()
	for _, file := range intermediateFiles {
		certificates, err := parsePEMCertificates(file)
		if err != nil {
			return rejected(err), nil
		}
		for _, certificate := range certificates {
			intermediates.AddCert(certificate)
		}
	}

	leafCertificates, err := parsePEMCertificates(leafFile)
	if err != nil {
		return rejected(err), nil
	}
	if len(leafCertificates) != 1 {
		return rejected(&certificateParseError{
			reason: "malformed_certificate",
			err:    fmt.Errorf("leaf %q contains %d certificates; expected exactly one", leafFile.path, len(leafCertificates)),
		}), nil
	}

	chains, err := leafCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       cfg.dnsName,
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   cfg.validationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return rejected(err), nil
	}
	return decision{
		Validator:  validatorName,
		Accepted:   true,
		Status:     statusAccept,
		Reason:     "accepted",
		Diagnostic: boundedDiagnostic(fmt.Sprintf("verified %d chain(s)", len(chains))),
	}, nil
}

func readCertificateFiles(paths []string) ([]certificateFile, error) {
	files := make([]certificateFile, 0, len(paths))
	for _, path := range paths {
		file, err := readCertificateFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func readCertificateFile(path string) (certificateFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return certificateFile{}, fmt.Errorf("open certificate file %q: %w", path, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxPEMFileSize+1))
	if err != nil {
		return certificateFile{}, fmt.Errorf("read certificate file %q: %w", path, err)
	}
	loaded := certificateFile{path: path, contents: contents}
	if len(contents) > maxPEMFileSize {
		loaded.contents = nil
		loaded.contentIssue = fmt.Sprintf("certificate file %q exceeds the %d-byte limit", path, maxPEMFileSize)
	}
	return loaded, nil
}

func parsePEMCertificates(file certificateFile) ([]*x509.Certificate, error) {
	if file.contentIssue != "" {
		return nil, &certificateParseError{reason: "resource_limit", err: errors.New(file.contentIssue)}
	}

	remaining := file.contents
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, &certificateParseError{
				reason: "malformed_certificate",
				err:    fmt.Errorf("certificate file %q contains malformed PEM data", file.path),
			}
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			return nil, &certificateParseError{
				reason: "malformed_certificate",
				err:    fmt.Errorf("certificate file %q contains unexpected PEM block %q", file.path, block.Type),
			}
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &certificateParseError{
				reason: classifyParseError(err),
				err:    fmt.Errorf("parse certificate in %q: %w", file.path, err),
			}
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, &certificateParseError{
			reason: "malformed_certificate",
			err:    fmt.Errorf("certificate file %q contains no CERTIFICATE PEM block", file.path),
		}
	}
	return certificates, nil
}

func rejected(reason error) decision {
	classification := classifyError(reason)
	return decision{
		Validator:  validatorName,
		Accepted:   false,
		Status:     classification.status,
		Reason:     classification.reason,
		Diagnostic: boundedDiagnostic(reason.Error()),
	}
}

func classifyError(err error) classifiedError {
	var parseErr *certificateParseError
	if errors.As(err, &parseErr) {
		status := statusReject
		if parseErr.reason == "resource_limit" {
			status = statusToolFailure
		}
		return classifiedError{status: status, reason: parseErr.reason}
	}

	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return classifiedError{status: statusReject, reason: "identity_mismatch"}
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return classifiedError{status: statusReject, reason: "untrusted_or_incomplete_path"}
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return classifyInvalidReason(invalid.Reason)
	}
	var constraint x509.ConstraintViolationError
	if errors.As(err, &constraint) {
		return classifiedError{status: statusReject, reason: "key_usage_failure"}
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) {
		return classifiedError{status: statusReject, reason: "signature_algorithm_invalid"}
	}
	var unhandled x509.UnhandledCriticalExtension
	if errors.As(err, &unhandled) {
		return classifiedError{status: statusReject, reason: "unknown_critical_extension"}
	}
	var systemRoots x509.SystemRootsError
	if errors.As(err, &systemRoots) {
		return classifiedError{status: statusToolFailure, reason: "oracle_failure"}
	}
	return classifiedError{status: statusReject, reason: "unclassified_rejection"}
}

func classifyInvalidReason(reason x509.InvalidReason) classifiedError {
	switch reason {
	case x509.NotAuthorizedToSign:
		return classifiedError{status: statusReject, reason: "key_usage_failure"}
	case x509.Expired:
		return classifiedError{status: statusReject, reason: "validity_failure"}
	case x509.CANotAuthorizedForThisName, x509.NameConstraintsWithoutSANs, x509.UnconstrainedName:
		return classifiedError{status: statusReject, reason: "name_constraints_violation"}
	case x509.TooManyIntermediates:
		return classifiedError{status: statusReject, reason: "path_length_violation"}
	case x509.IncompatibleUsage, x509.CANotAuthorizedForExtKeyUsage:
		return classifiedError{status: statusReject, reason: "extended_key_usage_failure"}
	case x509.NameMismatch, x509.NoValidChains:
		return classifiedError{status: statusReject, reason: "untrusted_or_incomplete_path"}
	case x509.TooManyConstraints:
		return classifiedError{status: statusToolFailure, reason: "resource_limit"}
	default:
		return classifiedError{status: statusReject, reason: "unclassified_rejection"}
	}
}

// Go does not export typed parse reasons. Keep the compatibility seam small,
// centralized, and bounded; any new diagnostic stays unclassified until a
// fixture and focused test deliberately add it.
func classifyParseError(err error) string {
	message := boundedDiagnostic(err.Error())
	switch {
	case strings.Contains(message, "duplicate extension"):
		return "duplicate_extension"
	case strings.Contains(message, "inner and outer signature algorithm identifiers don't match"):
		return "signature_algorithm_invalid"
	case strings.Contains(message, "Ed25519 key encoded with illegal parameters"),
		strings.Contains(message, "malformed public key"),
		strings.Contains(message, "invalid RSA public key"):
		return "issuer_key_or_spki_invalid"
	case strings.Contains(message, "malformed signature"):
		return "signature_algorithm_invalid"
	case strings.Contains(message, "malformed certificate"),
		strings.Contains(message, "asn1:"),
		strings.Contains(message, "trailing data"):
		return "malformed_der"
	default:
		return "unclassified_rejection"
	}
}

func boundedDiagnostic(message string) string {
	if len(message) <= maxDiagnosticSize {
		return message
	}

	const suffix = "..."
	end := maxDiagnosticSize - len(suffix)
	for end > 0 && !utf8.RuneStart(message[end]) {
		end--
	}
	return message[:end] + suffix
}
