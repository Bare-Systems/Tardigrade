#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm ED25519 -out "$tmp/root.key"
openssl req -new -x509 -key "$tmp/root.key" -days 3650 -set_serial 1 \
  -subj "/CN=Tardigrade Name Constraints Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$script_dir/root.crt"

cat >"$tmp/constrained-ca.cnf" <<'EOF'
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
nameConstraints = critical,@constraints

[constraints]
permitted;DNS.1 = example.com
excluded;DNS.1 = blocked.example.com
permitted;IP.1 = 192.0.2.0/255.255.255.0
permitted;dirName.1 = permitted_dn

[permitted_dn]
O = Bare Systems
EOF

openssl genpkey -algorithm ED25519 -out "$tmp/intermediate.key"
openssl req -new -key "$tmp/intermediate.key" -subj "/CN=Constrained Intermediate" -out "$tmp/intermediate.csr"
openssl x509 -req -in "$tmp/intermediate.csr" -CA "$script_dir/root.crt" -CAkey "$tmp/root.key" \
  -set_serial 2 -days 3650 -extfile "$tmp/constrained-ca.cnf" -extensions v3_ca \
  -out "$script_dir/intermediate.crt"

issue_leaf() {
  local name="$1"
  local serial="$2"
  local subject="$3"
  local san="$4"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "$subject" -out "$tmp/$name.csr"
  cat >"$tmp/$name.cnf" <<EOF
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = $san
EOF
  openssl x509 -req -in "$tmp/$name.csr" -CA "$script_dir/intermediate.crt" -CAkey "$tmp/intermediate.key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions leaf \
    -out "$script_dir/$name.crt"
}

issue_leaf dns-good 10 "/O=Bare Systems/CN=DNS Good" "DNS:api.example.com"
issue_leaf dns-excluded 11 "/O=Bare Systems/CN=DNS Excluded" "DNS:blocked.example.com"
issue_leaf ip-good 12 "/O=Bare Systems/CN=IP Good" "IP:192.0.2.255"
issue_leaf ip-bad 13 "/O=Bare Systems/CN=IP Bad" "IP:192.0.3.1"
issue_leaf directory-bad 14 "/O=Other/CN=Directory Bad" "DNS:api.example.com"

cat >"$tmp/leading-dot-ca.cnf" <<'EOF'
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
nameConstraints = critical,permitted;DNS:.example.com
EOF

openssl genpkey -algorithm ED25519 -out "$tmp/leading-dot.key"
openssl req -new -key "$tmp/leading-dot.key" -subj "/CN=Leading Dot Intermediate" -out "$tmp/leading-dot.csr"
openssl x509 -req -in "$tmp/leading-dot.csr" -CA "$script_dir/root.crt" -CAkey "$tmp/root.key" \
  -set_serial 20 -days 3650 -extfile "$tmp/leading-dot-ca.cnf" -extensions v3_ca \
  -out "$script_dir/leading-dot-intermediate.crt"

issue_leading_dot_leaf() {
  local name="$1"
  local serial="$2"
  local dns="$3"
  openssl genpkey -algorithm ED25519 -out "$tmp/$name.key"
  openssl req -new -key "$tmp/$name.key" -subj "/CN=$name" -out "$tmp/$name.csr"
  cat >"$tmp/$name.cnf" <<EOF
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$dns
EOF
  openssl x509 -req -in "$tmp/$name.csr" -CA "$script_dir/leading-dot-intermediate.crt" -CAkey "$tmp/leading-dot.key" \
    -set_serial "$serial" -days 3650 -extfile "$tmp/$name.cnf" -extensions leaf \
    -out "$script_dir/$name.crt"
}

issue_leading_dot_leaf leading-dot-subdomain 21 sub.example.com
issue_leading_dot_leaf leading-dot-exact 22 example.com

openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/intermediate.crt" "$script_dir/dns-good.crt"
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/intermediate.crt" "$script_dir/dns-excluded.crt"; then exit 1; fi
openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/intermediate.crt" "$script_dir/ip-good.crt"
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/intermediate.crt" "$script_dir/ip-bad.crt"; then exit 1; fi
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/intermediate.crt" "$script_dir/directory-bad.crt"; then exit 1; fi
openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/leading-dot-intermediate.crt" "$script_dir/leading-dot-subdomain.crt"
if openssl verify -CAfile "$script_dir/root.crt" -untrusted "$script_dir/leading-dot-intermediate.crt" "$script_dir/leading-dot-exact.crt"; then exit 1; fi
