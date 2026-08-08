#!/usr/bin/env bash
# Installs the external TLS conformance peers on a Debian/Ubuntu CI runner
# (#338). The #338 matrix drives two independent implementations as separate
# processes: OpenSSL (already on the runner image) and the second peer this
# script adds. Neither is ever linked into Tardigrade.
#
# Kept under scripts/interop/, the audited external-peer boundary
# (scripts/audit-dependencies.sh) -- the peer package names are only safe to
# write inside this directory, which is why the CI workflow calls this script
# instead of naming them inline.
#
# See docs/TLS_INTEROP_MATRIX.md for what the matrix does with these peers.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y gnutls-bin openssl

# Report what the matrix will actually be running against, so a CI log records
# the peer versions a given result was produced with.
openssl version
gnutls-cli --version | head -1
