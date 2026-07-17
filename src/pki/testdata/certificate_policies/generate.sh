#!/usr/bin/env bash
# Regenerates the fixed certificate-policy fixtures.  Only the public
# certificates are committed; private keys live and die in a temp directory.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

OID1="1.3.6.1.4.1.99999.1"
OID2="1.3.6.1.4.1.99999.2"

openssl genpkey -algorithm ED25519 -out "$tmp/root.key"
openssl req -new -x509 -key "$tmp/root.key" -days 3650 -set_serial 1 \
  -subj "/CN=Tardigrade Policy Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$script_dir/root.crt"

# issue_ca <name> <serial> <issuer-name> <extra v3 lines...>
issue_ca() {
  local name="$1" serial="$2" issuer="$3"
  shift 3
  local issuer_key="$tmp/root.key" issuer_crt="$script_dir/root.crt"
  if [ "$issuer" != root ]; then
    issuer_key="$tmp/$issuer.key"
    issuer_crt="$script_dir/$issuer.crt"
  fi
  {
    echo "[v3_ca]"
    echo "basicConstraints = critical,CA:TRUE"
    echo "keyUsage = critical,keyCertSign,cRLSign"
    for line in "$@"; do echo "$line"; done
  } >"$tmp/$name.cnf"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "/CN=Tardigrade Policy $name" -out "$tmp/$name.csr"
  openssl x509 -req -in "$tmp/$name.csr" -CA "$issuer_crt" -CAkey "$issuer_key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions v3_ca \
    -out "$script_dir/$name.crt"
}

# issue_leaf <name> <serial> <issuer-name> [policies]
issue_leaf() {
  local name="$1" serial="$2" issuer="$3" policies="${4:-}"
  {
    echo "[leaf]"
    echo "basicConstraints = critical,CA:FALSE"
    echo "keyUsage = critical,digitalSignature"
    echo "extendedKeyUsage = serverAuth"
    echo "subjectAltName = DNS:$name.example.com"
    if [ -n "$policies" ]; then
      echo "certificatePolicies = $policies"
    fi
  } >"$tmp/$name.cnf"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "/CN=Tardigrade Policy $name" -out "$tmp/$name.csr"
  openssl x509 -req -in "$tmp/$name.csr" -CA "$script_dir/$issuer.crt" -CAkey "$tmp/$issuer.key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions leaf \
    -out "$script_dir/$name.crt"
}

# Direct explicit-policy success and missing-policy failure.
issue_ca policy-intermediate 10 root "certificatePolicies = $OID1"
issue_leaf leaf-policy1 11 policy-intermediate "$OID1"
issue_leaf leaf-policy2 12 policy-intermediate "$OID2"

# anyPolicy propagation and inhibition.
issue_ca any-intermediate 20 root "certificatePolicies = 2.5.29.32.0"
issue_leaf any-leaf 21 any-intermediate "$OID1"
issue_ca inhibit-ca1 22 root "certificatePolicies = 2.5.29.32.0" "inhibitAnyPolicy = critical,0"
issue_ca inhibit-ca2 23 inhibit-ca1 "certificatePolicies = 2.5.29.32.0"
issue_leaf inhibit-leaf 24 inhibit-ca2 "$OID1"

# Simple mapping and mapping inhibited by an intermediate policyConstraints.
issue_ca mapping-intermediate 30 root "certificatePolicies = $OID1" "policyMappings = $OID1:$OID2"
issue_leaf mapping-leaf 31 mapping-intermediate "$OID2"
issue_ca mapinhibit-ca1 32 root "certificatePolicies = $OID1" "policyConstraints = critical,inhibitPolicyMapping:0"
issue_ca mapinhibit-ca2 33 mapinhibit-ca1 "certificatePolicies = $OID1" "policyMappings = $OID1:$OID2"
issue_leaf mapinhibit-leaf 34 mapinhibit-ca2 "$OID2"

# requireExplicitPolicy without a leaf policy.
issue_ca rep-intermediate 40 root "certificatePolicies = $OID1" "policyConstraints = critical,requireExplicitPolicy:0"
issue_leaf rep-leaf 41 rep-intermediate
