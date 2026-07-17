//go:build ignore

// generate.go creates the project-owned hostile PKI fixtures in this directory.
// It deliberately writes certificates only: deterministic fixture signing keys
// are derived and used in memory, then discarded when the process exits.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const validationTimeUnix = 1784332800 // 2026-07-18T00:00:00Z

var (
	notBefore = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2036, time.January, 1, 0, 0, 0, 0, time.UTC)

	// RFC 5612 reserves PEN 32473 for examples and documentation.
	unknownCriticalOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 348, 1}
	duplicateOID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 348, 2}
)

type keyPair struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

type certificate struct {
	der    []byte
	parsed *x509.Certificate
}

// zeroReader makes any unexpected entropy request reproducible. Ed25519
// signing itself does not consume randomness.
type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func main() {
	out := flag.String("out", ".", "directory that receives generated fixtures")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	rootKey := deterministicKey("shared-root")
	rootTemplate := caTemplate(100, "Tardigrade Hostile Fixture Root", 4)
	root, err := selfSigned(rootTemplate, rootKey)
	if err != nil {
		return fmt.Errorf("create shared root: %w", err)
	}

	intermediateKey := deterministicKey("shared-intermediate")
	intermediate, err := issue(
		caTemplate(101, "Tardigrade Hostile Fixture Intermediate", 0),
		root.parsed,
		intermediateKey,
		rootKey.private,
	)
	if err != nil {
		return fmt.Errorf("create shared intermediate: %w", err)
	}

	validKey := deterministicKey("valid-leaf")
	valid, err := issue(
		leafTemplate(110, "Valid Chain Leaf", "api.example.test"),
		intermediate.parsed,
		validKey,
		intermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create valid leaf: %w", err)
	}

	wildcardKey := deterministicKey("wildcard-leaf")
	wildcard, err := issue(
		leafTemplate(111, "Wildcard Edge Leaf", "*.example.test"),
		intermediate.parsed,
		wildcardKey,
		intermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create wildcard leaf: %w", err)
	}

	unknownTemplate := leafTemplate(112, "Unknown Critical Extension Leaf", "critical.example.test")
	unknownTemplate.ExtraExtensions = []pkix.Extension{{
		Id:       unknownCriticalOID,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // DER NULL
	}}
	unknownKey := deterministicKey("unknown-critical-leaf")
	unknownCritical, err := issue(
		unknownTemplate,
		intermediate.parsed,
		unknownKey,
		intermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create unknown-critical leaf: %w", err)
	}

	signatureCorruptDER := append([]byte(nil), valid.der...)
	signatureCorruptDER[len(signatureCorruptDER)-1] ^= 0x01
	signatureCorrupt, err := x509.ParseCertificate(signatureCorruptDER)
	if err != nil {
		return fmt.Errorf("signature-corrupt leaf must remain parseable: %w", err)
	}

	pathLenZeroKey := deterministicKey("pathlen-zero-ca")
	pathLenZero, err := issue(
		caTemplate(120, "PathLen Zero CA", 0),
		root.parsed,
		pathLenZeroKey,
		rootKey.private,
	)
	if err != nil {
		return fmt.Errorf("create pathLen=0 CA: %w", err)
	}

	pathLenSubordinateKey := deterministicKey("pathlen-subordinate-ca")
	pathLenSubordinate, err := issue(
		caTemplate(121, "CA Below PathLen Zero", 0),
		pathLenZero.parsed,
		pathLenSubordinateKey,
		pathLenZeroKey.private,
	)
	if err != nil {
		return fmt.Errorf("create pathLen subordinate: %w", err)
	}

	pathLenLeafKey := deterministicKey("pathlen-leaf")
	pathLenLeaf, err := issue(
		leafTemplate(122, "PathLen Violation Leaf", "pathlen.example.test"),
		pathLenSubordinate.parsed,
		pathLenLeafKey,
		pathLenSubordinateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create pathLen leaf: %w", err)
	}

	crossRootAKey := deterministicKey("cross-root-a")
	crossRootA, err := selfSigned(caTemplate(200, "Cross Root A", 2), crossRootAKey)
	if err != nil {
		return fmt.Errorf("create cross root A: %w", err)
	}
	crossRootBKey := deterministicKey("cross-root-b")
	crossRootB, err := selfSigned(caTemplate(201, "Cross Root B", 2), crossRootBKey)
	if err != nil {
		return fmt.Errorf("create cross root B: %w", err)
	}

	// These two certificates deliberately carry the same subject and public
	// key. The B-signed certificate is ordered first in the untrusted bundle,
	// and both roots are trusted by the stable ambiguous-path case.
	crossIntermediateKey := deterministicKey("cross-intermediate")
	crossIntermediateA, err := issue(
		caTemplate(202, "Cross-Signed Intermediate", 0),
		crossRootA.parsed,
		crossIntermediateKey,
		crossRootAKey.private,
	)
	if err != nil {
		return fmt.Errorf("create A-signed intermediate: %w", err)
	}
	crossIntermediateB, err := issue(
		caTemplate(203, "Cross-Signed Intermediate", 0),
		crossRootB.parsed,
		crossIntermediateKey,
		crossRootBKey.private,
	)
	if err != nil {
		return fmt.Errorf("create B-signed intermediate: %w", err)
	}
	crossLeafKey := deterministicKey("cross-leaf")
	crossLeaf, err := issue(
		leafTemplate(204, "Ambiguous Path Leaf", "cross.example.test"),
		crossIntermediateA.parsed,
		crossLeafKey,
		crossIntermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create cross-sign leaf: %w", err)
	}

	duplicateTemplate := leafTemplate(130, "Duplicate Extension Leaf", "duplicate.example.test")
	duplicateTemplate.ExtraExtensions = []pkix.Extension{
		{Id: duplicateOID, Critical: true, Value: []byte{0x05, 0x00}},
		{Id: duplicateOID, Critical: true, Value: []byte{0x05, 0x00}},
	}
	duplicateKey := deterministicKey("duplicate-extension-leaf")
	duplicateDER, err := createDER(
		duplicateTemplate,
		intermediate.parsed,
		duplicateKey,
		intermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create duplicate-extension leaf: %w", err)
	}
	if _, err := x509.ParseCertificate(duplicateDER); err == nil {
		return fmt.Errorf("duplicate-extension leaf unexpectedly parsed in Go")
	}

	malformedDER := append([]byte(nil), valid.der[:len(valid.der)/2]...)
	if _, err := x509.ParseCertificate(malformedDER); err == nil {
		return fmt.Errorf("truncated DER seed unexpectedly parsed in Go")
	}

	validationTime := time.Unix(validationTimeUnix, 0).UTC()
	if err := expectVerify(true, valid.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "api.example.test", validationTime); err != nil {
		return fmt.Errorf("valid chain: %w", err)
	}
	if err := expectVerify(true, wildcard.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "api.example.test", validationTime); err != nil {
		return fmt.Errorf("wildcard single label: %w", err)
	}
	if err := expectVerify(false, wildcard.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "example.test", validationTime); err != nil {
		return fmt.Errorf("wildcard apex: %w", err)
	}
	if err := expectVerify(false, wildcard.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "deep.api.example.test", validationTime); err != nil {
		return fmt.Errorf("wildcard multiple labels: %w", err)
	}
	if err := expectVerify(false, unknownCritical.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "critical.example.test", validationTime); err != nil {
		return fmt.Errorf("unknown critical extension: %w", err)
	}
	if err := expectVerify(false, signatureCorrupt, []*x509.Certificate{root.parsed}, []*x509.Certificate{intermediate.parsed}, "api.example.test", validationTime); err != nil {
		return fmt.Errorf("corrupt signature: %w", err)
	}
	if err := expectVerify(false, pathLenLeaf.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{pathLenSubordinate.parsed, pathLenZero.parsed}, "pathlen.example.test", validationTime); err != nil {
		return fmt.Errorf("pathLen violation: %w", err)
	}
	if err := expectVerify(true, crossLeaf.parsed, []*x509.Certificate{crossRootA.parsed, crossRootB.parsed}, []*x509.Certificate{crossIntermediateB.parsed, crossIntermediateA.parsed}, "cross.example.test", validationTime); err != nil {
		return fmt.Errorf("cross-sign alternate path: %w", err)
	}

	files := map[string][]byte{
		"root.crt":                     encodeCertificate(root.der),
		"intermediate.crt":             encodeCertificate(intermediate.der),
		"valid-leaf.crt":               encodeCertificate(valid.der),
		"wildcard-leaf.crt":            encodeCertificate(wildcard.der),
		"unknown-critical-leaf.crt":    encodeCertificate(unknownCritical.der),
		"signature-corrupt-leaf.crt":   encodeCertificate(signatureCorruptDER),
		"pathlen-zero-ca.crt":          encodeCertificate(pathLenZero.der),
		"pathlen-subordinate-ca.crt":   encodeCertificate(pathLenSubordinate.der),
		"pathlen-chain.crt":            encodeBundle(pathLenSubordinate.der, pathLenZero.der),
		"pathlen-leaf.crt":             encodeCertificate(pathLenLeaf.der),
		"cross-root-a.crt":             encodeCertificate(crossRootA.der),
		"cross-root-b.crt":             encodeCertificate(crossRootB.der),
		"cross-roots.crt":              encodeBundle(crossRootA.der, crossRootB.der),
		"cross-intermediate-a.crt":     encodeCertificate(crossIntermediateA.der),
		"cross-intermediate-b.crt":     encodeCertificate(crossIntermediateB.der),
		"cross-untrusted-b-first.crt":  encodeBundle(crossIntermediateB.der, crossIntermediateA.der),
		"cross-leaf.crt":               encodeCertificate(crossLeaf.der),
		"duplicate-extension-leaf.crt": encodeCertificate(duplicateDER),
		"malformed-truncated.crt":      encodeCertificate(malformedDER),
		"malformed-truncated.der":      malformedDER,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(out, name), contents, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func deterministicKey(label string) keyPair {
	seed := sha256.Sum256([]byte("Tardigrade issue 348 hostile PKI fixture: " + label))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	return keyPair{public: public, private: private}
}

func subjectKeyID(public ed25519.PublicKey) []byte {
	digest := sha256.Sum256(public)
	return append([]byte(nil), digest[:20]...)
}

func baseTemplate(serial int64, commonName string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       big.NewInt(serial),
		SignatureAlgorithm: x509.PureEd25519,
		Subject: pkix.Name{
			Organization: []string{"Bare Systems Test Fixtures"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
}

func caTemplate(serial int64, commonName string, maxPathLen int) *x509.Certificate {
	template := baseTemplate(serial, commonName)
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.MaxPathLen = maxPathLen
	template.MaxPathLenZero = maxPathLen == 0
	return template
}

func leafTemplate(serial int64, commonName, dnsName string) *x509.Certificate {
	template := baseTemplate(serial, commonName)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames = []string{dnsName}
	return template
}

func selfSigned(template *x509.Certificate, key keyPair) (certificate, error) {
	return issue(template, template, key, key.private)
}

func issue(template, parent *x509.Certificate, subject keyPair, signer ed25519.PrivateKey) (certificate, error) {
	der, err := createDER(template, parent, subject, signer)
	if err != nil {
		return certificate{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return certificate{}, err
	}
	return certificate{der: der, parsed: parsed}, nil
}

func createDER(template, parent *x509.Certificate, subject keyPair, signer ed25519.PrivateKey) ([]byte, error) {
	template.SubjectKeyId = subjectKeyID(subject.public)
	return x509.CreateCertificate(zeroReader{}, template, parent, subject.public, signer)
}

func expectVerify(
	want bool,
	leaf *x509.Certificate,
	roots []*x509.Certificate,
	intermediates []*x509.Certificate,
	dnsName string,
	validationTime time.Time,
) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		DNSName:       dnsName,
		CurrentTime:   validationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	got := err == nil
	if got != want {
		return fmt.Errorf("got accepted=%t, want accepted=%t: %v", got, want, err)
	}
	return nil
}

func encodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeBundle(certificates ...[]byte) []byte {
	var bundle []byte
	for _, der := range certificates {
		bundle = append(bundle, encodeCertificate(der)...)
	}
	return bundle
}
