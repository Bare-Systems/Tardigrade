#!/bin/sh
# Generate the interop test certificates (#247): one Ed25519 identity (the
# native stack's default profile; accepted by GnuTLS/OpenSSL peers) and one
# ECDSA P-256 identity (required by BoringSSL-based peers such as quiche,
# whose default verifier does not offer Ed25519).
#
# usage: gen-certs.sh OUT_DIR
set -eu

out="${1:?usage: gen-certs.sh OUT_DIR}"
mkdir -p "$out"

gen() { # name algo-args...
  name="$1"
  shift
  openssl genpkey "$@" -out "$out/$name-key.pem" 2>/dev/null
  openssl req -new -x509 -key "$out/$name-key.pem" -out "$out/$name-cert.pem" -days 30 \
    -subj "/CN=tardigrade.test" \
    -addext "subjectAltName=DNS:tardigrade.test,IP:127.0.0.1" 2>/dev/null
  openssl x509 -in "$out/$name-cert.pem" -outform DER -out "$out/$name-cert.der"
  openssl pkcs8 -topk8 -nocrypt -in "$out/$name-key.pem" -outform DER -out "$out/$name-key.pkcs8.der"
}

gen ed25519 -algorithm ed25519
gen p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256

echo "certificates written to $out"
