//go:build ignore

// generate.go creates the project-owned hostile PKI fixtures in this directory.
// It deliberately writes certificates only: deterministic fixture signing keys
// are derived and used in memory, then discarded when the process exits.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
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

	dnsConstraintsTemplate := caTemplate(102, "DNS-only Name Constraints Intermediate", 0)
	dnsConstraintsTemplate.PermittedDNSDomainsCritical = true
	dnsConstraintsTemplate.PermittedDNSDomains = []string{"example.test"}
	dnsConstraintsTemplate.ExcludedDNSDomains = []string{"blocked.example.test"}
	dnsConstraintsKey := deterministicKey("dns-constraints-intermediate")
	dnsConstraints, err := issue(dnsConstraintsTemplate, root.parsed, dnsConstraintsKey, rootKey.private)
	if err != nil {
		return fmt.Errorf("create DNS constraints intermediate: %w", err)
	}
	dnsPermitted, err := issue(
		leafTemplate(103, "DNS Permitted Leaf", "api.example.test"),
		dnsConstraints.parsed,
		deterministicKey("dns-permitted-leaf"),
		dnsConstraintsKey.private,
	)
	if err != nil {
		return fmt.Errorf("create DNS permitted leaf: %w", err)
	}
	dnsExcluded, err := issue(
		leafTemplate(104, "DNS Excluded Leaf", "blocked.example.test"),
		dnsConstraints.parsed,
		deterministicKey("dns-excluded-leaf"),
		dnsConstraintsKey.private,
	)
	if err != nil {
		return fmt.Errorf("create DNS excluded leaf: %w", err)
	}

	ipConstraintsTemplate := caTemplate(105, "IP-only Name Constraints Intermediate", 0)
	ipConstraintsTemplate.PermittedDNSDomainsCritical = true // marks the Name Constraints extension critical
	ipConstraintsTemplate.PermittedIPRanges = []*net.IPNet{{
		IP:   net.IPv4(192, 0, 2, 0),
		Mask: net.CIDRMask(24, 32),
	}}
	ipConstraintsTemplate.ExcludedIPRanges = []*net.IPNet{{
		IP:   net.IPv4(192, 0, 2, 128),
		Mask: net.CIDRMask(25, 32),
	}}
	ipConstraintsKey := deterministicKey("ip-constraints-intermediate")
	ipConstraints, err := issue(ipConstraintsTemplate, root.parsed, ipConstraintsKey, rootKey.private)
	if err != nil {
		return fmt.Errorf("create IP constraints intermediate: %w", err)
	}
	ipPermittedTemplate := leafTemplate(106, "IP Permitted Leaf", "ip.example.test")
	ipPermittedTemplate.IPAddresses = []net.IP{net.IPv4(192, 0, 2, 42)}
	ipPermitted, err := issue(ipPermittedTemplate, ipConstraints.parsed, deterministicKey("ip-permitted-leaf"), ipConstraintsKey.private)
	if err != nil {
		return fmt.Errorf("create IP permitted leaf: %w", err)
	}
	ipExcludedTemplate := leafTemplate(107, "IP Excluded Leaf", "ip-blocked.example.test")
	ipExcludedTemplate.IPAddresses = []net.IP{net.IPv4(192, 0, 2, 200)}
	ipExcluded, err := issue(ipExcludedTemplate, ipConstraints.parsed, deterministicKey("ip-excluded-leaf"), ipConstraintsKey.private)
	if err != nil {
		return fmt.Errorf("create IP excluded leaf: %w", err)
	}

	identityMismatch, err := issue(
		leafTemplate(108, "Isolated Identity Leaf", "identity.example.test"),
		intermediate.parsed,
		deterministicKey("identity-mismatch-leaf"),
		intermediateKey.private,
	)
	if err != nil {
		return fmt.Errorf("create isolated identity leaf: %w", err)
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

	algorithmFixtures, err := hostileAlgorithmFixtures(valid.der, intermediateKey.private)
	if err != nil {
		return fmt.Errorf("create algorithm fixtures: %w", err)
	}
	derFixtures, err := hostileDERFixtures(valid.der, intermediateKey.private)
	if err != nil {
		return fmt.Errorf("create DER fixtures: %w", err)
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
	if err := expectVerify(true, dnsPermitted.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{dnsConstraints.parsed}, "api.example.test", validationTime); err != nil {
		return fmt.Errorf("DNS constraints permitted: %w", err)
	}
	if err := expectVerify(false, dnsExcluded.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{dnsConstraints.parsed}, "blocked.example.test", validationTime); err != nil {
		return fmt.Errorf("DNS constraints excluded: %w", err)
	}
	if err := expectVerify(true, ipPermitted.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{ipConstraints.parsed}, "", validationTime); err != nil {
		return fmt.Errorf("IP constraints permitted: %w", err)
	}
	if err := expectVerify(false, ipExcluded.parsed, []*x509.Certificate{root.parsed}, []*x509.Certificate{ipConstraints.parsed}, "", validationTime); err != nil {
		return fmt.Errorf("IP constraints excluded: %w", err)
	}

	files := map[string][]byte{
		"root.crt":                         encodeCertificate(root.der),
		"intermediate.crt":                 encodeCertificate(intermediate.der),
		"dns-constraints-intermediate.crt": encodeCertificate(dnsConstraints.der),
		"dns-permitted-leaf.crt":           encodeCertificate(dnsPermitted.der),
		"dns-excluded-leaf.crt":            encodeCertificate(dnsExcluded.der),
		"ip-constraints-intermediate.crt":  encodeCertificate(ipConstraints.der),
		"ip-permitted-leaf.crt":            encodeCertificate(ipPermitted.der),
		"ip-excluded-leaf.crt":             encodeCertificate(ipExcluded.der),
		"identity-mismatch-leaf.crt":       encodeCertificate(identityMismatch.der),
		"valid-leaf.crt":                   encodeCertificate(valid.der),
		"wildcard-leaf.crt":                encodeCertificate(wildcard.der),
		"unknown-critical-leaf.crt":        encodeCertificate(unknownCritical.der),
		"signature-corrupt-leaf.crt":       encodeCertificate(signatureCorruptDER),
		"pathlen-zero-ca.crt":              encodeCertificate(pathLenZero.der),
		"pathlen-subordinate-ca.crt":       encodeCertificate(pathLenSubordinate.der),
		"pathlen-chain.crt":                encodeBundle(pathLenSubordinate.der, pathLenZero.der),
		"pathlen-leaf.crt":                 encodeCertificate(pathLenLeaf.der),
		"cross-root-a.crt":                 encodeCertificate(crossRootA.der),
		"cross-root-b.crt":                 encodeCertificate(crossRootB.der),
		"cross-roots.crt":                  encodeBundle(crossRootA.der, crossRootB.der),
		"cross-intermediate-a.crt":         encodeCertificate(crossIntermediateA.der),
		"cross-intermediate-b.crt":         encodeCertificate(crossIntermediateB.der),
		"cross-untrusted-b-first.crt":      encodeBundle(crossIntermediateB.der, crossIntermediateA.der),
		"cross-leaf.crt":                   encodeCertificate(crossLeaf.der),
		"duplicate-extension-leaf.crt":     encodeCertificate(duplicateDER),
		"malformed-truncated.crt":          encodeCertificate(malformedDER),
		"malformed-truncated.der":          malformedDER,
	}
	for name, der := range algorithmFixtures {
		files[name+".crt"] = encodeCertificate(der)
		files[name+".der"] = der
	}
	for name, der := range derFixtures {
		files[name+".crt"] = encodeCertificate(der)
		files[name+".der"] = der
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

var ed25519AlgorithmIdentifier = []byte{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70}

type certificateParts struct {
	tbs                []byte
	signatureAlgorithm []byte
	signatureValue     []byte
}

func hostileAlgorithmFixtures(validDER []byte, signer ed25519.PrivateKey) (map[string][]byte, error) {
	unsupported := []byte{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71}
	malformedOID := []byte{0x30, 0x06, 0x06, 0x04, 0x2b, 0x65, 0x80, 0x70}
	ed25519Null := []byte{0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00}

	outerMismatch, err := mutateOuterAlgorithm(validDER, unsupported)
	if err != nil {
		return nil, err
	}
	unsupportedSignature, err := mutateSignatureAlgorithms(validDER, unsupported, signer)
	if err != nil {
		return nil, err
	}
	malformedSignatureOID, err := mutateSignatureAlgorithms(validDER, malformedOID, signer)
	if err != nil {
		return nil, err
	}
	ed25519Parameters, err := mutateSignatureAlgorithms(validDER, ed25519Null, signer)
	if err != nil {
		return nil, err
	}
	malformedSPKI, err := mutateSPKIAlgorithm(validDER, malformedOID, signer)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"algorithm-outer-inner-mismatch":       outerMismatch,
		"algorithm-unsupported-signature-oid":  unsupportedSignature,
		"algorithm-malformed-signature-oid":    malformedSignatureOID,
		"algorithm-ed25519-illegal-parameters": ed25519Parameters,
		"algorithm-malformed-spki":             malformedSPKI,
	}, nil
}

func hostileDERFixtures(validDER []byte, signer ed25519.PrivateKey) (map[string][]byte, error) {
	parts, err := splitCertificate(validDER)
	if err != nil {
		return nil, err
	}
	_, outerContent, err := splitTLV(validDER)
	if err != nil {
		return nil, err
	}

	nonMinimalLength := append([]byte{0x30, 0x83, 0x00, byte(len(outerContent) >> 8), byte(len(outerContent))}, outerContent...)
	indefiniteLength := append([]byte{0x30, 0x80}, outerContent...)
	indefiniteLength = append(indefiniteLength, 0x00, 0x00)
	truncatedLength := []byte{0x30, 0x82, 0x01}

	nonMinimalIntegerTBS, err := replaceNthInSequence(parts.tbs, []byte{0x02, 0x01, 0x6e}, []byte{0x02, 0x02, 0x00, 0x6e}, 0)
	if err != nil {
		return nil, err
	}
	nonMinimalInteger := signCertificateWithTBS(nonMinimalIntegerTBS, parts.signatureAlgorithm, signer)

	invalidUnusedBits, err := mutateSignatureBitString(validDER, func(content []byte) { content[0] = 8 })
	if err != nil {
		return nil, err
	}
	nonzeroPadding, err := mutateSignatureBitString(validDER, func(content []byte) {
		content[0] = 1
		content[len(content)-1] |= 1
	})
	if err != nil {
		return nil, err
	}
	constructedBitString := append([]byte(nil), validDER...)
	partsOffset := bytes.LastIndex(constructedBitString, parts.signatureValue)
	if partsOffset < 0 {
		return nil, fmt.Errorf("signature BIT STRING not found")
	}
	constructedBitString[partsOffset] = 0x23
	trailingData := append(append([]byte(nil), validDER...), 0x05, 0x00)

	malformedNested := append([]byte(nil), parts.tbs...)
	sanOID := []byte{0x06, 0x03, 0x55, 0x1d, 0x11}
	sanOffset := bytes.Index(malformedNested, sanOID)
	if sanOffset < 0 {
		return nil, fmt.Errorf("subjectAltName OID not found")
	}
	octetOffset := bytes.IndexByte(malformedNested[sanOffset+len(sanOID):], 0x04)
	if octetOffset < 0 {
		return nil, fmt.Errorf("subjectAltName OCTET STRING not found")
	}
	octetOffset += sanOffset + len(sanOID)
	malformedNested[octetOffset+1] = 0x7f
	malformedNestedLength := signCertificateWithTBS(malformedNested, parts.signatureAlgorithm, signer)

	return map[string][]byte{
		"der-non-minimal-long-length":        nonMinimalLength,
		"der-indefinite-length":              indefiniteLength,
		"der-truncated-long-length":          truncatedLength,
		"der-non-minimal-integer":            nonMinimalInteger,
		"der-invalid-bit-string-unused":      invalidUnusedBits,
		"der-nonzero-bit-string-padding":     nonzeroPadding,
		"der-constructed-bit-string":         constructedBitString,
		"der-trailing-data":                  trailingData,
		"der-malformed-nested-extension-len": malformedNestedLength,
	}, nil
}

func mutateOuterAlgorithm(der, algorithm []byte) ([]byte, error) {
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, err
	}
	return joinCertificate(parts.tbs, algorithm, parts.signatureValue), nil
}

func mutateSignatureAlgorithms(der, algorithm []byte, signer ed25519.PrivateKey) ([]byte, error) {
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, err
	}
	tbs, err := replaceNthInSequence(parts.tbs, ed25519AlgorithmIdentifier, algorithm, 0)
	if err != nil {
		return nil, err
	}
	return signCertificateWithTBS(tbs, algorithm, signer), nil
}

func mutateSPKIAlgorithm(der, algorithm []byte, signer ed25519.PrivateKey) ([]byte, error) {
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, err
	}
	tbs, err := replaceNthInSequence(parts.tbs, ed25519AlgorithmIdentifier, algorithm, 1)
	if err != nil {
		return nil, err
	}
	return signCertificateWithTBS(tbs, parts.signatureAlgorithm, signer), nil
}

func mutateSignatureBitString(der []byte, mutate func([]byte)) ([]byte, error) {
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, err
	}
	tag, content, err := splitTLV(parts.signatureValue)
	if err != nil || tag != 0x03 || len(content) == 0 {
		return nil, fmt.Errorf("malformed source signature BIT STRING")
	}
	owned := append([]byte(nil), content...)
	mutate(owned)
	return joinCertificate(parts.tbs, parts.signatureAlgorithm, wrapTLV(0x03, owned)), nil
}

func splitCertificate(der []byte) (certificateParts, error) {
	tag, content, err := splitTLV(der)
	if err != nil || tag != 0x30 {
		return certificateParts{}, fmt.Errorf("certificate is not one DER SEQUENCE")
	}
	first, rest, err := takeTLV(content)
	if err != nil {
		return certificateParts{}, err
	}
	second, rest, err := takeTLV(rest)
	if err != nil {
		return certificateParts{}, err
	}
	third, rest, err := takeTLV(rest)
	if err != nil || len(rest) != 0 {
		return certificateParts{}, fmt.Errorf("certificate does not have three elements")
	}
	return certificateParts{tbs: first, signatureAlgorithm: second, signatureValue: third}, nil
}

func joinCertificate(tbs, algorithm, signature []byte) []byte {
	content := make([]byte, 0, len(tbs)+len(algorithm)+len(signature))
	content = append(content, tbs...)
	content = append(content, algorithm...)
	content = append(content, signature...)
	return wrapTLV(0x30, content)
}

func signCertificateWithTBS(tbs, algorithm []byte, signer ed25519.PrivateKey) []byte {
	signature := ed25519.Sign(signer, tbs)
	content := make([]byte, 1, 1+len(signature))
	content[0] = 0
	content = append(content, signature...)
	return joinCertificate(tbs, algorithm, wrapTLV(0x03, content))
}

func replaceNthInSequence(sequence, old, replacement []byte, nth int) ([]byte, error) {
	tag, content, err := splitTLV(sequence)
	if err != nil || tag != 0x30 {
		return nil, fmt.Errorf("mutation target is not a sequence")
	}
	offset := 0
	for occurrence := 0; ; occurrence++ {
		found := bytes.Index(content[offset:], old)
		if found < 0 {
			return nil, fmt.Errorf("mutation pattern occurrence %d not found", nth)
		}
		found += offset
		if occurrence == nth {
			mutated := make([]byte, 0, len(content)-len(old)+len(replacement))
			mutated = append(mutated, content[:found]...)
			mutated = append(mutated, replacement...)
			mutated = append(mutated, content[found+len(old):]...)
			return wrapTLV(tag, mutated), nil
		}
		offset = found + len(old)
	}
}

func takeTLV(input []byte) ([]byte, []byte, error) {
	_, _, total, err := parseTLV(input)
	if err != nil {
		return nil, nil, err
	}
	return input[:total], input[total:], nil
}

func splitTLV(input []byte) (byte, []byte, error) {
	tag, header, total, err := parseTLV(input)
	if err != nil {
		return 0, nil, err
	}
	if total != len(input) {
		return 0, nil, fmt.Errorf("trailing bytes after DER element")
	}
	return tag, input[header:total], nil
}

func parseTLV(input []byte) (tag byte, header, total int, err error) {
	if len(input) < 2 {
		return 0, 0, 0, fmt.Errorf("truncated DER element")
	}
	tag = input[0]
	length := int(input[1])
	header = 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(input) < 2+count {
			return 0, 0, 0, fmt.Errorf("invalid DER length")
		}
		length = 0
		for _, octet := range input[2 : 2+count] {
			length = length<<8 | int(octet)
		}
		header += count
	}
	total = header + length
	if total > len(input) {
		return 0, 0, 0, fmt.Errorf("DER length exceeds input")
	}
	return tag, header, total, nil
}

func wrapTLV(tag byte, content []byte) []byte {
	result := []byte{tag}
	switch {
	case len(content) < 0x80:
		result = append(result, byte(len(content)))
	case len(content) <= 0xff:
		result = append(result, 0x81, byte(len(content)))
	default:
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	return append(result, content...)
}
