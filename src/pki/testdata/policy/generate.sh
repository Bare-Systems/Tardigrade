#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

policy_a="1.3.6.1.4.1.55555.1"
policy_b="1.3.6.1.4.1.55555.2"

openssl genpkey -algorithm ED25519 -out "$tmp/root.key"
openssl req -new -x509 -key "$tmp/root.key" -days 3650 -set_serial 100 \
  -subj "/CN=Tardigrade Policy Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$script_dir/root.crt"

issue_ca() {
  local name="$1"
  local serial="$2"
  local extra="$3"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "/CN=$name" -out "$tmp/$name.csr"
  cat >"$tmp/$name.cnf" <<EOF
[ca]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
certificatePolicies = $policy_a
$extra
EOF
  openssl x509 -req -in "$tmp/$name.csr" -CA "$script_dir/root.crt" -CAkey "$tmp/root.key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions ca \
    -out "$script_dir/$name.crt"
}

cat >"$tmp/mapping-asn1.cnf" <<EOF
asn1 = SEQUENCE:mappings
[mappings]
mapping = SEQUENCE:mapping
[mapping]
issuer = OID:$policy_a
subject = OID:$policy_b
EOF
openssl asn1parse -genconf "$tmp/mapping-asn1.cnf" -out "$tmp/mapping.der" >/dev/null
mapping_hex="$(od -An -v -tx1 "$tmp/mapping.der" | tr -d ' \n' | sed 's/../&:/g;s/:$//')"

issue_ca direct-intermediate 101 ""
issue_ca mapping-intermediate 102 "2.5.29.33 = critical,DER:$mapping_hex"
issue_ca explicit-intermediate 103 "policyConstraints = critical,requireExplicitPolicy:0"
issue_ca mapping-constraint-upper 104 "policyConstraints = critical,inhibitPolicyMapping:0"
issue_ca inhibit-any-intermediate 105 "inhibitAnyPolicy = critical,0"

openssl genpkey -algorithm ED25519 -out "$tmp/mapping-constraint-lower.key"
openssl req -new -key "$tmp/mapping-constraint-lower.key" -subj "/CN=mapping-constraint-lower" -out "$tmp/mapping-constraint-lower.csr"
cat >"$tmp/mapping-constraint-lower.cnf" <<EOF
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
certificatePolicies = $policy_a
2.5.29.33 = critical,DER:$mapping_hex
EOF
openssl x509 -req -in "$tmp/mapping-constraint-lower.csr" \
  -CA "$script_dir/mapping-constraint-upper.crt" -CAkey "$tmp/mapping-constraint-upper.key" \
  -set_serial 106 -days 3650 -extfile "$tmp/mapping-constraint-lower.cnf" -extensions ca \
  -out "$script_dir/mapping-constraint-lower.crt"

issue_leaf() {
  local name="$1"
  local serial="$2"
  local issuer="$3"
  local policies="$4"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "/CN=$name" -out "$tmp/$name.csr"
  cat >"$tmp/$name.cnf" <<EOF
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
$policies
EOF
  openssl x509 -req -in "$tmp/$name.csr" -CA "$script_dir/$issuer.crt" -CAkey "$tmp/$issuer.key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions leaf \
    -out "$script_dir/$name.crt"
}

issue_leaf direct-leaf 110 direct-intermediate "certificatePolicies = $policy_a"
issue_leaf missing-leaf 111 direct-intermediate ""
issue_leaf any-leaf 112 direct-intermediate "certificatePolicies = 2.5.29.32.0"
issue_leaf mapped-leaf 113 mapping-intermediate "certificatePolicies = $policy_b"
issue_leaf explicit-missing-leaf 114 explicit-intermediate ""
issue_leaf constrained-mapped-leaf 115 mapping-constraint-lower "certificatePolicies = $policy_b"
issue_leaf extension-inhibited-any-leaf 116 inhibit-any-intermediate "certificatePolicies = 2.5.29.32.0"
{
  cat "$script_dir/mapping-constraint-lower.crt"
  cat "$script_dir/mapping-constraint-upper.crt"
} >"$script_dir/mapping-constraint-chain.crt"

verify_policy() {
  local intermediate="$1"
  local leaf="$2"
  shift 2
  openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/$intermediate.crt" \
    -policy "$policy_a" -explicit_policy "$@" "$script_dir/$leaf.crt"
}

verify_policy direct-intermediate direct-leaf
if verify_policy direct-intermediate missing-leaf; then exit 1; fi
verify_policy direct-intermediate any-leaf
if verify_policy direct-intermediate any-leaf -inhibit_any; then exit 1; fi
verify_policy mapping-intermediate mapped-leaf
if verify_policy mapping-intermediate mapped-leaf -inhibit_map; then exit 1; fi
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/explicit-intermediate.crt" \
  -policy "$policy_a" -policy_check "$script_dir/explicit-missing-leaf.crt"; then exit 1; fi
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/mapping-constraint-chain.crt" \
  -policy "$policy_a" -explicit_policy "$script_dir/constrained-mapped-leaf.crt"; then exit 1; fi
if verify_policy inhibit-any-intermediate extension-inhibited-any-leaf; then exit 1; fi
