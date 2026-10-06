#!/bin/sh
# Regenerates the downstream client-certificate fixtures used by the HTTP/3
# mTLS tests (#763). Everything is Ed25519, the native stack's default
# profile. Validity windows are fixed (not "now"-relative) so the suite never
# ages out: valid certificates run 2026-2096, the "expired" certificate ended
# in 2020 and the "not yet valid" one starts in 2090.
#
# CA private keys are discarded after signing: nothing in the tests needs to
# mint further certificates, and a committed CA key is a liability. Re-run
# this script to rotate the whole set.
#
# usage: tests/fixtures/tls/h3mtls/gen.sh   (from the repository root)
set -eu

out="$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

NB=20260101000000Z
NA=20960101000000Z

genkey() { openssl genpkey -algorithm ed25519 -out "$1" 2>/dev/null; }

mkca() { # name cn
  genkey "$work/$1.key"
  openssl req -new -x509 -key "$work/$1.key" -subj "/CN=$2" \
    -not_before "$NB" -not_after "$NA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$out/$1.crt" 2>/dev/null
}

mkleaf() { # name ca cn eku not_before not_after [san]
  name="$1"; ca="$2"; cn="$3"; eku="$4"; nb="$5"; na="$6"; san="${7:-}"
  genkey "$work/$name.key"
  openssl pkcs8 -topk8 -nocrypt -in "$work/$name.key" -outform DER -out "$out/$name.key.der"
  openssl req -new -key "$work/$name.key" -subj "/CN=$cn" -out "$work/$name.csr" 2>/dev/null
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    [ -n "$eku" ] && echo "extendedKeyUsage=$eku"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$work/$name.ext"
  openssl x509 -req -in "$work/$name.csr" -CA "$out/$ca.crt" -CAkey "$work/$ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -not_before "$nb" -not_after "$na" \
    -extfile "$work/$name.ext" -out "$out/$name.crt" 2>/dev/null
  openssl x509 -in "$out/$name.crt" -outform DER -out "$out/$name.der"
}

mkca ca "Tardigrade H3 mTLS Test CA"
mkca rogue_ca "Tardigrade H3 mTLS Rogue CA"

mkleaf client ca "h3-client.example" clientAuth "$NB" "$NA" \
  "DNS:h3-client.example,email:h3@example.com,URI:spiffe://example/h3-client"
mkleaf client_expired ca "h3-expired.example" clientAuth 20200101000000Z 20200102000000Z
mkleaf client_not_yet_valid ca "h3-future.example" clientAuth 20900101000000Z "$NA"
mkleaf client_wrong_eku ca "h3-serverauth.example" serverAuth "$NB" "$NA"
mkleaf client_wrong_ca rogue_ca "h3-rogue.example" clientAuth "$NB" "$NA"

echo "fixtures written to $out"
