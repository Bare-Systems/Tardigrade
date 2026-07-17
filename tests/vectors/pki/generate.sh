#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
validation_time=1784332800
tmp="$(mktemp -d)"

fixtures=(
  root.crt
  intermediate.crt
  valid-leaf.crt
  wildcard-leaf.crt
  unknown-critical-leaf.crt
  signature-corrupt-leaf.crt
  pathlen-zero-ca.crt
  pathlen-subordinate-ca.crt
  pathlen-chain.crt
  pathlen-leaf.crt
  cross-root-a.crt
  cross-root-b.crt
  cross-roots.crt
  cross-intermediate-a.crt
  cross-intermediate-b.crt
  cross-untrusted-b-first.crt
  cross-leaf.crt
  duplicate-extension-leaf.crt
  malformed-truncated.crt
  malformed-truncated.der
)

cleanup() {
  for fixture in "${fixtures[@]}"; do
    rm -f "$script_dir/$fixture.new"
  done
  rm -rf "$tmp"
}
trap cleanup EXIT

go run "$script_dir/generate.go" -out "$tmp/first"
go run "$script_dir/generate.go" -out "$tmp/second"
diff -ru "$tmp/first" "$tmp/second"

openssl_accept() {
  if ! openssl verify -attime "$validation_time" -purpose sslserver "$@" >/dev/null 2>&1; then
    echo "OpenSSL unexpectedly rejected: $*" >&2
    exit 1
  fi
}

openssl_reject() {
  if openssl verify -attime "$validation_time" -purpose sslserver "$@" >/dev/null 2>&1; then
    echo "OpenSSL unexpectedly accepted: $*" >&2
    exit 1
  else
    status=$?
    if [[ "$status" -ne 2 ]]; then
      echo "OpenSSL verification tool failed with exit $status: $*" >&2
      exit 1
    fi
  fi
}

out="$tmp/first"
openssl_accept -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname api.example.test "$out/valid-leaf.crt"
openssl_accept -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname api.example.test "$out/wildcard-leaf.crt"
openssl_reject -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname example.test "$out/wildcard-leaf.crt"
openssl_reject -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname deep.api.example.test "$out/wildcard-leaf.crt"
openssl_reject -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname critical.example.test "$out/unknown-critical-leaf.crt"
openssl_reject -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
  -verify_hostname api.example.test "$out/signature-corrupt-leaf.crt"
openssl_reject -trusted "$out/root.crt" -untrusted "$out/pathlen-chain.crt" \
  -verify_hostname pathlen.example.test "$out/pathlen-leaf.crt"
openssl_accept -trusted "$out/cross-roots.crt" -untrusted "$out/cross-untrusted-b-first.crt" \
  -verify_hostname cross.example.test "$out/cross-leaf.crt"

# Duplicate extensions must be rejected either by the parser or by validation.
if openssl x509 -in "$out/duplicate-extension-leaf.crt" -noout >/dev/null 2>&1; then
  openssl_reject -trusted "$out/root.crt" -untrusted "$out/intermediate.crt" \
    -verify_hostname duplicate.example.test "$out/duplicate-extension-leaf.crt"
fi
if openssl x509 -inform DER -in "$out/malformed-truncated.der" -noout >/dev/null 2>&1; then
  echo "OpenSSL unexpectedly parsed malformed-truncated.der" >&2
  exit 1
fi
if openssl x509 -in "$out/malformed-truncated.crt" -noout >/dev/null 2>&1; then
  echo "OpenSSL unexpectedly parsed malformed-truncated.crt" >&2
  exit 1
fi

# Refuse stale files and any persisted private-key material. This directory is
# deliberately closed: every regular file must be authored here or generated
# by the manifest above.
authored=(README.md generate.go generate.sh)
while IFS= read -r -d '' existing; do
  name="${existing##*/}"
  found=false
  for fixture in "${fixtures[@]}"; do
    if [[ "$fixture" == "$name" ]]; then
      found=true
      break
    fi
  done
  if [[ "$found" == false ]]; then
    for source_file in "${authored[@]}"; do
      if [[ "$source_file" == "$name" ]]; then
        found=true
        break
      fi
    done
  fi
  if [[ "$found" == false ]]; then
    echo "unexpected file is not in the PKI fixture manifest: $name" >&2
    exit 1
  fi
  if grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$existing"; then
    echo "private-key material found in fixture directory: $name" >&2
    exit 1
  fi
done < <(find "$script_dir" -maxdepth 1 -type f -print0)
for certificate_file in "$out"/*.crt; do
  if grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$certificate_file"; then
    echo "private-key material found in generated fixture: ${certificate_file##*/}" >&2
    exit 1
  fi
  if grep -aE '^-----BEGIN ' "$certificate_file" | grep -vqx -- '-----BEGIN CERTIFICATE-----'; then
    echo "unexpected PEM block found in generated fixture: ${certificate_file##*/}" >&2
    exit 1
  fi
done

# The reduced regression corpus is likewise closed: only `manifest.zig` and
# kebab-case `.der` seeds registered as entry names in it, all immediate
# regular files (no nesting, no symlinks), none containing private-key
# material.
reduced_dir="$script_dir/reduced"
if [[ -d "$reduced_dir" ]]; then
  while IFS= read -r -d '' entry; do
    rel="${entry#"$reduced_dir/"}"
    if [[ "$rel" == */* || -L "$entry" || ! -f "$entry" ]]; then
      echo "unexpected nested, symlinked, or non-file entry in reduced corpus: $rel" >&2
      exit 1
    fi
    if [[ "$rel" != manifest.zig ]]; then
      if [[ "$rel" != *.der ]]; then
        echo "unexpected file in reduced corpus: $rel" >&2
        exit 1
      fi
      base="${rel%.der}"
      if [[ ! "$base" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
        echo "reduced seed name is not kebab-case: $rel" >&2
        exit 1
      fi
      # Match the structured registration line, not any string occurrence.
      if ! grep -Eq "^[[:space:]]*entry\(\"$base\", \.\{\$" "$reduced_dir/manifest.zig"; then
        echo "reduced seed is not registered as an entry in manifest.zig: $rel" >&2
        exit 1
      fi
    fi
    if grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$entry"; then
      echo "private-key material found in reduced corpus: $rel" >&2
      exit 1
    fi
  done < <(find "$reduced_dir" -mindepth 1 -print0)
  # Reverse direction: every registered entry must have its seed file (the
  # registry derives the embed path from the entry name, so a matching file
  # must exist).
  while IFS= read -r registered; do
    if [[ ! -f "$reduced_dir/$registered.der" ]]; then
      echo "manifest.zig entry has no seed file: $registered" >&2
      exit 1
    fi
  done < <(grep -Eo '^[[:space:]]*entry\("[a-z0-9-]+", \.\{$' "$reduced_dir/manifest.zig" | sed -E 's/.*"([a-z0-9-]+)".*/\1/')
fi

# Publish only after both generators and both validators agree.
for fixture in "${fixtures[@]}"; do
  install -m 0644 "$out/$fixture" "$script_dir/$fixture.new"
done
for fixture in "${fixtures[@]}"; do
  mv "$script_dir/$fixture.new" "$script_dir/$fixture"
done
