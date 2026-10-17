#!/bin/sh
# Regenerates the loopback TLS identity for the real ACME CA test server
# (#883 P1: `src/acme/live_ca_server.zig`). Ed25519, the native stack's
# default profile, matching the house style of `../h3mtls/gen.sh`. The leaf
# carries only an IP SAN for 127.0.0.1 (no DNS name): the test dials the CA
# by its literal loopback address, so that is the identity the production
# A2 client's hostname verification actually checks. Validity is fixed
# (not "now"-relative) so the suite never ages out: 2026-2096.
#
# The CA private key is discarded after signing: nothing in the tests needs
# to mint further certificates, and a committed CA key is a liability.
# Re-run this script to rotate the whole set.
#
# usage: tests/fixtures/tls/acme_live_ca/gen.sh   (from the repository root)
set -eu

out="$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

NB=20260101000000Z
NA=20960101000000Z

genkey() { openssl genpkey -algorithm ed25519 -out "$1" 2>/dev/null; }

genkey "$work/ca.key"
openssl req -new -x509 -key "$work/ca.key" -subj "/CN=Tardigrade ACME Live Test CA" \
  -not_before "$NB" -not_after "$NA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/ca.crt" 2>/dev/null

genkey "$out/leaf.key"
openssl req -new -key "$out/leaf.key" -subj "/CN=127.0.0.1" -out "$work/leaf.csr" 2>/dev/null
{
  echo "basicConstraints=critical,CA:FALSE"
  echo "keyUsage=critical,digitalSignature"
  echo "extendedKeyUsage=serverAuth"
  echo "subjectAltName=IP:127.0.0.1"
} >"$work/leaf.ext"
openssl x509 -req -in "$work/leaf.csr" -CA "$out/ca.crt" -CAkey "$work/ca.key" \
  -set_serial "0x$(openssl rand -hex 8)" -not_before "$NB" -not_after "$NA" \
  -extfile "$work/leaf.ext" -out "$out/leaf.crt" 2>/dev/null

echo "fixtures written to $out"
