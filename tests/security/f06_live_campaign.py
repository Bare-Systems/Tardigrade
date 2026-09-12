#!/usr/bin/env python3
"""Live black-box campaign for #673 (F-06: auth enforcement + hostile framing).

Fires raw, byte-exact HTTP/1.1 requests at a running `tardi` process fronting
the disposable upstream in tests/security/fixtures/f06_upstream.py, and
asserts -- from the upstream's own hit log, not just the client-visible
status code -- that:

  * every missing/malformed-credential case is denied *before* the protected
    upstream is ever invoked, with no exceptions for cases where one of two
    duplicate values happens to be valid;
  * method, path, and Host variations cannot move a request off the
    protected boundary;
  * client-supplied X-Tardigrade-* / X-Forwarded-* identity headers never
    become the trusted identity forwarded upstream, and cannot rewrite the
    rate-limit/access-log client identity from an untrusted connection;
  * TE/CL conflicts, chunked-encoding abuse, and duplicate/oversized headers
    are rejected without ever dispatching a smuggled follow-up request --
    proven with a unique marker request appended to every applicable probe;
  * the static traversal boundary (including symlink escape and an
    alias-rooted location) cannot be crossed;
  * a deliberately hostile upstream cannot split or desync the downstream
    connection: neither a fresh connection nor the *same* downstream
    connection used for the hostile probe can be corrupted by it, and a
    "ghost" second response cannot bleed into an unrelated later response
    over a reused upstream connection.

Run with the hardened trust posture (TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY=true,
TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES not including the test client's
address) via scripts/run-f06-auth-framing-campaign.sh, which owns process
lifecycle (build, start upstream + tardi, teardown) and evidence capture.
Curl is deliberately not used: it normalizes malformed syntax this campaign
needs to send byte-exact.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import socket
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass

VALID_TOKEN = "f06-valid-token-9f3c2a9b7e"
JWT_SECRET = "f06-jwt-secret-do-not-use-in-prod-4c1a"
TRAVERSAL_CANARY = "F06_TRAVERSAL_CANARY_SHOULD_NEVER_BE_SERVED"
ALIAS_ROOT_CANARY = "F06_ALIAS_ROOT_OK"
GHOST_MARKER = "F06_UPSTREAM_GHOST_MARKER"
# Must match tests/security/fixtures/f06_upstream.py's DELAYED_GHOST_SCENARIO
# / DELAYED_GHOST_DELAY_SECONDS / DELAYED_GHOST_AFTER_CONTENT_LENGTH_SCENARIO
# / DELAYED_GHOST_AFTER_CHUNKED_SCENARIO -- the fixture runs as a separate
# process, so these can't be shared via import.
DELAYED_GHOST_SCENARIO = "delayed_ghost_after_bodiless"
DELAYED_GHOST_DELAY_SECONDS = 0.35
DELAYED_GHOST_AFTER_CONTENT_LENGTH_SCENARIO = "delayed_ghost_after_content_length"
DELAYED_GHOST_AFTER_CHUNKED_SCENARIO = "delayed_ghost_after_chunked"

# Distinctive bytes for each hostile-upstream scenario that must never
# appear verbatim in a later, unrelated response if the downstream
# connection (or the upstream connection pool behind it) is desynchronized.
SCENARIO_LEAK_MARKERS: dict[str, bytes] = {
    "malformed_status_line": b"20O WEIRD",
    "ctl_and_bare_cr_in_header_value": b"with-ctl-and-bare-cr",
    "truncated_body": b"short",
    "unusual_1xx_chain": b"Early Hints",
    "invalid_204_with_body": b"nope!",
    "invalid_304_with_body": b"nope!",
    "upgrade_101_attempt": b"websocket",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_hs256_jwt(secret: str, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


@dataclass
class Result:
    name: str
    category: str
    ok: bool
    detail: str = ""


RESULTS: list[Result] = []


def record(name: str, category: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(Result(name, category, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {category}: {name}" + (f" -- {detail}" if detail and not ok else ""))


# --- transport helpers -------------------------------------------------

def send_raw(port: int, data: bytes, read_timeout: float = 1.2, connect_timeout: float = 2.0) -> bytes:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=connect_timeout) as s:
            s.sendall(data)
            s.settimeout(read_timeout)
            chunks = []
            total = 0
            try:
                while total < 1_000_000:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
            except (socket.timeout, ConnectionResetError):
                pass
            return b"".join(chunks)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
        return b""


def send_raw_then_close_early(port: int, first: bytes, rest: bytes, delay: float = 0.15) -> bytes:
    """Send `first`, wait, send `rest`, then close without waiting for the rest -- used
    for premature-EOF / declared-but-not-delivered body cases."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
            s.sendall(first)
            time.sleep(delay)
            if rest:
                s.sendall(rest)
            s.settimeout(0.6)
            try:
                return s.recv(4096)
            except (socket.timeout, ConnectionResetError):
                return b""
    except OSError:
        return b""


def first_status_code(raw: bytes) -> int | None:
    if not raw.startswith(b"HTTP/"):
        return None
    nl = raw.find(b"\n")
    if nl == -1:
        return None
    parts = raw[:nl].split(b" ", 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def response_headers_lower(raw: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    head_end = raw.find(b"\r\n\r\n")
    head = raw[: head_end if head_end != -1 else len(raw)]
    lines = head.split(b"\r\n")[1:]
    for line in lines:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return out


# --- upstream control ---------------------------------------------------

class Upstream:
    def __init__(self, port: int):
        self.port = port

    def reset(self) -> None:
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/reset", timeout=2).read()

    def hits(self) -> list[dict]:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/hits", timeout=2) as r:
            return json.load(r)["hits"]


# --- assertions -----------------------------------------------------------

def assert_denied(up: Upstream, name: str, category: str, port: int, request: bytes) -> None:
    up.reset()
    raw = send_raw(port, request)
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    detail = f"status={status} upstream_hits={len(hits)} resp_head={raw[:80]!r}"
    record(name, category, ok, detail)


def assert_allowed(up: Upstream, name: str, category: str, port: int, request: bytes, expect_path_substr: str) -> dict | None:
    up.reset()
    raw = send_raw(port, request)
    status = first_status_code(raw)
    hits = up.hits()
    matching = [h for h in hits if expect_path_substr in h["path"]]
    ok = status == 200 and len(matching) >= 1
    detail = f"status={status} upstream_hits={len(hits)} resp_head={raw[:120]!r}"
    record(name, category, ok, detail)
    return matching[0] if matching else None


def framing_marker_case(up: Upstream, name: str, cat: str, port: int, build_raw) -> None:
    """
    Smuggling oracle applied to every applicable hostile-framing probe
    (#673 review): `build_raw(marker_tail)` returns a complete byte stream
    for one malformed/ambiguous request with `marker_tail` -- a full,
    syntactically valid pipelined GET for a unique per-case path -- appended
    immediately after it. If Tardigrade ever mis-measures where the
    malformed request "ends" and starts parsing trailing bytes as a fresh
    request, the marker path would show up in the upstream's hit log.
    Passes only if the protected upstream sees zero hits at all -- neither
    the malformed request itself nor the smuggled marker was ever
    dispatched.
    """
    marker_path = f"/f06-marker-{name}"
    marker_tail = f"GET {marker_path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
    raw_request = build_raw(marker_tail)
    up.reset()
    resp = send_raw(port, raw_request, read_timeout=1.3)
    hits = up.hits()
    # Diagnostic only: the pass/fail gate below is `len(hits) == 0`, which
    # does not depend on the exact forwarded path shape (proxy_pass may
    # rewrite the location prefix, e.g. inserting a "/"). Match on the
    # unique case name rather than the full marker_path so this stays
    # accurate regardless of that rewrite.
    smuggled = any(name in h["path"] for h in hits)
    status = first_status_code(resp)
    ok = len(hits) == 0
    record(name, cat, ok, f"status={status} hits={len(hits)} smuggled={smuggled}")


def hostile_same_socket_reuse(up: Upstream, name: str, cat: str, port: int, scenario: str, path: str = "/hostile") -> None:
    """
    Same-downstream-connection desync proof (#673 review, both passes): open
    ONE TCP connection to tardi, send the hostile-upstream probe, then --
    on that SAME socket, without reconnecting -- send a second, ordinary
    request and inspect what comes back.

    Critically, the FIRST response is validated too (a prior version of
    this helper only inspected `second`, so a hostile upstream that
    corrupted Tardigrade's very first reply to the client -- e.g. leaking
    the ghost marker or splitting into more than one apparent response --
    would pass as long as the connection then happened to close). A dirty
    first response is an immediate fail regardless of what happens next.

    Given a clean first response, two outcomes for the second request are
    accepted as safe:
      (a) tardi closed the connection afterward (the strictest possible
          mitigation -- no reuse risk at all); or
      (b) tardi kept it open and the second response is a single,
          well-formed response that contains none of the first (hostile)
          response's distinguishing bytes.
    """
    up.reset()
    leak_marker = SCENARIO_LEAK_MARKERS.get(scenario, b"")
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
    except OSError as e:
        record(name, cat, False, f"connect failed: {e}")
        return
    try:
        s.sendall(req("GET", path, [("X-F06-Scenario", scenario)]))
        s.settimeout(1.0)
        first = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                first += chunk
        except (socket.timeout, ConnectionResetError):
            pass

        # Tardigrade consumes 1xx interim responses internally and forwards
        # only the actual final response (#673 review), so every scenario's
        # healthy first response -- unusual_1xx_chain included -- is exactly
        # one status line; anything else is a corrupted/split response.
        first_status_lines = first.count(b"HTTP/1.")
        first_leaked = bool(leak_marker) and leak_marker in first
        first_ghosted = GHOST_MARKER.encode() in first
        first_corrupted = first_status_lines > 1 or first_leaked or first_ghosted
        if first_corrupted:
            record(name, cat, False,
                   f"first response already corrupted: status_lines={first_status_lines} "
                   f"leaked={first_leaked} ghosted={first_ghosted} first_head={first[:150]!r}")
            return

        second_send_failed = False
        try:
            s.sendall(req("GET", path, [("X-F06-Scenario", "")]))
        except OSError:
            second_send_failed = True

        second = b""
        if not second_send_failed:
            s.settimeout(1.0)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    second += chunk
            except (socket.timeout, ConnectionResetError):
                pass
    finally:
        s.close()

    if second_send_failed or not second:
        record(name, cat, True, "connection closed after a clean first response (no reuse -- safe)")
        return

    status_line_count = second.count(b"HTTP/1.")
    leaked = bool(leak_marker) and leak_marker in second
    ghosted = GHOST_MARKER.encode() in second
    ok = status_line_count == 1 and not leaked and not ghosted
    record(name, cat, ok,
           f"status_lines_in_second={status_line_count} leaked={leaked} ghosted={ghosted} first_len={len(first)}")


# --- case builders ----------------------------------------------------

def req(method: str, path: str, headers: list[tuple[str, str]], body: bytes = b"", version: str = "HTTP/1.1", host: str = "localhost") -> bytes:
    lines = [f"{method} {path} {version}"]
    has_host = any(k.lower() == "host" for k, _ in headers)
    if not has_host and version == "HTTP/1.1":
        lines.append(f"Host: {host}")
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if body and not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1") + body


def run_auth_matrix(up: Upstream, port: int) -> None:
    cat = "auth.missing_malformed_credentials"

    assert_denied(up, "no_authorization_header", cat, port, req("GET", "/protected", []))
    assert_denied(up, "bearer_scheme_no_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer")]))
    assert_denied(up, "bearer_scheme_empty_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer ")]))
    assert_allowed(up, "bearer_extra_internal_whitespace_still_valid", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer   {VALID_TOKEN}")]), "/protected")
    assert_denied(up, "wrong_scheme_basic", cat, port, req("GET", "/protected", [("Authorization", "Basic YWJjOmRlZg==")]))
    assert_denied(up, "wrong_scheme_arbitrary", cat, port, req("GET", "/protected", [("Authorization", "Digest abc")]))
    assert_denied(up, "malformed_token_two_parts", cat, port, req("GET", "/protected", [("Authorization", "Bearer bad token")]))
    assert_denied(up, "oversized_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer " + ("a" * 5000))]))
    assert_denied(up, "malformed_jwt_no_dots", cat, port, req("GET", "/protected", [("Authorization", "Bearer notavalidjwt")]))
    assert_denied(up, "malformed_jwt_bad_segments", cat, port, req("GET", "/protected", [("Authorization", "Bearer not.a.jwt")]))

    bad_sig_jwt = make_hs256_jwt("wrong-secret-entirely", {"sub": "attacker"})
    assert_denied(up, "invalid_jwt_signature", cat, port, req("GET", "/protected", [("Authorization", f"Bearer {bad_sig_jwt}")]))

    # Duplicate Authorization is ambiguous the same way duplicate
    # Content-Length is (fixed in src/http/request.zig -- rejected with
    # error.DuplicateAuthorizationHeader before routing/auth ever runs), so
    # this must be a strict deny in BOTH field orders, not merely
    # "client status agrees with whether upstream was hit" -- a request
    # that happens to authenticate because a valid token was one of the two
    # duplicated values is exactly the bypass #673 asks to close.
    assert_denied(up, "duplicate_authorization_invalid_then_valid", cat, port,
                  req("GET", "/protected", [("Authorization", "Bearer garbage"), ("Authorization", f"Bearer {VALID_TOKEN}")]))
    assert_denied(up, "duplicate_authorization_valid_then_invalid", cat, port,
                  req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}"), ("Authorization", "Bearer garbage")]))
    assert_denied(up, "comma_joined_authorization_variant", cat, port,
                  req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}, Bearer other-token")]))

    raw_nul = b"GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\x00def\r\n\r\n"
    up.reset()
    resp = send_raw(port, raw_nul)
    hits = up.hits()
    ok = (first_status_code(resp) is None or first_status_code(resp) >= 400) and len(hits) == 0
    record("nul_byte_in_authorization_value", cat, ok, f"status={first_status_code(resp)} hits={len(hits)}")

    raw_bare_cr = b"GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\rdef\r\n\r\n"
    up.reset()
    resp = send_raw(port, raw_bare_cr)
    hits = up.hits()
    ok = (first_status_code(resp) is None or first_status_code(resp) >= 400) and len(hits) == 0
    record("bare_cr_in_authorization_value", cat, ok, f"status={first_status_code(resp)} hits={len(hits)}")


def run_identity_spoofing(up: Upstream, port: int) -> None:
    cat = "auth.identity_spoofing"

    up.reset()
    raw = send_raw(port, req("GET", "/protected", [
        ("Authorization", f"Bearer {VALID_TOKEN}"),
        ("X-Tardigrade-Auth-Identity", "spoofed-admin"),
    ]))
    status = first_status_code(raw)
    hits = up.hits()
    forwarded_identity = None
    if hits:
        forwarded_identity = hits[0]["headers"].get("X-Tardigrade-Auth-Identity") or hits[0]["headers"].get("x-tardigrade-auth-identity")
    ok = status == 200 and len(hits) == 1 and forwarded_identity != "spoofed-admin"
    record("x_tardigrade_identity_header_not_trusted_from_client", cat, ok,
           f"status={status} forwarded_identity={forwarded_identity!r}")

    assert_denied(up, "x_forwarded_for_spoof_without_auth_does_not_bypass", cat, port,
                  req("GET", "/protected", [("X-Forwarded-For", "127.0.0.1")]))

    up.reset()
    raw = send_raw(port, req("GET", "/protected", [
        ("Authorization", f"Bearer {VALID_TOKEN}"),
        ("Connection", "X-Tardigrade-Auth-Identity"),
        ("X-Tardigrade-Auth-Identity", "spoofed-via-connection-nomination"),
    ]))
    status = first_status_code(raw)
    hits = up.hits()
    forwarded_identity = None
    if hits:
        forwarded_identity = hits[0]["headers"].get("X-Tardigrade-Auth-Identity") or hits[0]["headers"].get("x-tardigrade-auth-identity")
    ok = status == 200 and len(hits) == 1 and forwarded_identity != "spoofed-via-connection-nomination"
    record("connection_nominated_identity_header_not_trusted", cat, ok,
           f"status={status} forwarded_identity={forwarded_identity!r}")

    # #673 review: valid-auth X-Forwarded-* rotation must not let the
    # asserted client identity (used for rate limiting and access logging)
    # be freely rewritten by an untrusted connecting peer. The campaign runs
    # with TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY=true and
    # TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES excluding 127.0.0.1 (the Safe
    # Deployment Checklist's recommended hardened posture), so the test
    # client itself is an untrusted connecting peer -- every rotated,
    # forged X-Forwarded-For value must be ignored and the upstream must
    # always see the real loopback address instead.
    up.reset()
    forged_ips = ["6.6.6.6", "9.9.9.9", "1.1.1.1"]
    for ip in forged_ips:
        send_raw(port, req("GET", "/protected", [
            ("Authorization", f"Bearer {VALID_TOKEN}"),
            ("X-Forwarded-For", ip),
            ("X-Real-IP", ip),
        ]))
    hits = up.hits()
    forwarded_ips_seen = {h["headers"].get("X-Forwarded-For") for h in hits}
    real_ips_seen = {h["headers"].get("X-Real-IP") for h in hits}
    no_forged_ip_honored = not (forwarded_ips_seen & set(forged_ips)) and not (real_ips_seen & set(forged_ips))
    ok = len(hits) == len(forged_ips) and no_forged_ip_honored
    record("x_forwarded_for_rotation_does_not_rewrite_client_identity", cat, ok,
           f"forwarded_ips_seen={forwarded_ips_seen} real_ips_seen={real_ips_seen}")


def run_method_change_bypass(up: Upstream, port: int) -> None:
    cat = "auth.method_change_bypass"
    for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
        assert_denied(up, f"method_{method.lower()}_still_requires_auth", cat, port, req(method, "/protected", []))

    up.reset()
    raw = send_raw(port, b"CONNECT protected:443 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("method_connect_rejected_or_denied", cat, ok, f"status={status} hits={len(hits)}")


def run_path_canonicalization(up: Upstream, port: int) -> None:
    cat = "auth.path_canonicalization"
    variants = [
        ("exact_protected", "/protected"),
        ("trailing_slash", "/protected/"),
        ("duplicate_leading_slash", "//protected"),
        ("duplicate_slash_midpath", "/protected//x"),
        ("dot_segment", "/./protected"),
        ("parent_dot_segment", "/../protected"),
        ("percent_encoded_char", "/prot%65cted"),
        ("encoded_dot_dot", "/%2e%2e/protected"),
        ("double_encoded_dot_dot", "/%252e%252e/protected"),
        ("encoded_trailing_slash", "/protected%2f"),
        ("encoded_backslash", "/protected%5c.."),
        ("query_string_variant", "/protected?x=1"),
        ("query_traversal_attempt", "/protected?../../etc/passwd"),
    ]
    for name, path in variants:
        assert_denied(up, name, cat, port, req("GET", path, []))

    up.reset()
    raw = send_raw(port, req(
        "GET",
        "http://attacker.example/protected",
        [("Authorization", f"Bearer {VALID_TOKEN}")],
        host="localhost",
    ))
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("absolute_form_request_target_still_requires_auth", cat, ok, f"status={status} hits={len(hits)}")

    # Use otherwise-valid authentication so the duplicate Host field itself
    # is the only reason this request can be denied. The old probe omitted
    # auth, so it passed even when the parser accepted both Host fields and
    # routing simply rejected the request later for missing credentials.
    up.reset()
    raw = send_raw(port, (
        b"GET /protected HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Host: evil.example\r\n"
        b"Authorization: Bearer " + VALID_TOKEN.encode() + b"\r\n\r\n"
    ))
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("duplicate_host_header_conflicting_values", cat, ok, f"status={status} hits={len(hits)}")


def run_positive_control_and_replay(up: Upstream, port: int) -> None:
    cat = "auth.positive_control_and_replay"

    assert_allowed(up, "valid_bearer_reaches_protected_upstream", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]), "/protected")

    jwt = make_hs256_jwt(JWT_SECRET, {"sub": "f06-jwt-subject"})
    assert_allowed(up, "valid_jwt_reaches_protected_upstream", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer {jwt}")]), "/protected")

    up.reset()
    r1 = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))
    r2 = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))
    hits = up.hits()
    ok = first_status_code(r1) == 200 and first_status_code(r2) == 200 and len(hits) == 2
    record("sequential_bearer_reuse_both_succeed", cat, ok, f"hits={len(hits)}")

    up.reset()
    results: list[bytes] = [b"", b""]

    def fire(i: int) -> None:
        results[i] = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))

    t1 = threading.Thread(target=fire, args=(0,))
    t2 = threading.Thread(target=fire, args=(1,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    hits = up.hits()
    ok = first_status_code(results[0]) == 200 and first_status_code(results[1]) == 200 and len(hits) == 2
    record("concurrent_bearer_reuse_both_succeed_not_treated_one_time", cat, ok, f"hits={len(hits)}")


def run_hostile_framing(up: Upstream, port: int) -> None:
    cat = "framing.content_length_and_chunking"

    # Every case below is "smuggling-shaped": a complete (non-truncated)
    # malformed/ambiguous request where trailing bytes could plausibly be
    # reinterpreted as a fresh request if the parser mis-measures the body
    # boundary. Each is run through framing_marker_case(), which appends a
    # unique pipelined marker request and proves it is never dispatched
    # (#673 review point 3).
    #
    # Every probe carries a VALID Authorization header (#673 review round 7):
    # without it, "the upstream was never hit" is equally explained by the
    # /protected auth gate rejecting the (auth-less) request, regardless of
    # whether the framing parser itself would have accepted or rejected the
    # malformed/ambiguous body -- a parser bug that wrongly accepted one of
    # these as valid would still show zero hits, since the request never
    # gets past auth either way. With valid auth, a parser bug that
    # incorrectly accepts the framing is no longer masked: the request
    # sails past auth and actually reaches (and is visible at) the upstream.

    framing_marker_case(up, "duplicate_cl_equal_values", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nABCD" + tail)
    framing_marker_case(up, "duplicate_cl_conflicting_values_hides_second_request", cat, port, lambda tail:
                         (lambda body: b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 4\r\nContent-Length: "
                          + str(len(body)).encode() + b"\r\n\r\n" + body)(b"ABCD" + tail))
    framing_marker_case(up, "comma_separated_content_length", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 4, 4\r\n\r\nABCD" + tail)
    framing_marker_case(up, "negative_content_length", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: -1\r\n\r\n" + tail)
    framing_marker_case(up, "content_length_integer_overflow", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 99999999999999999999999999\r\n\r\n" + tail)
    framing_marker_case(up, "smuggling_probe_te_chunked_plus_cl", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 4\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "te_before_cl_header_order", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "te_cl_mixed_case_both_present", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\ncontent-length: 4\r\nTRANSFER-ENCODING: chunked\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "duplicate_transfer_encoding_fields", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "unsupported_transfer_coding_gzip_chunked", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "chunked_not_final_coding", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "invalid_chunk_size_hex", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "oversized_chunk_size_value", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n" + b"a" * 32 + b"\r\n0\r\n\r\n" + tail)
    framing_marker_case(up, "missing_crlf_after_chunk_data", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcdXXXX0\r\n\r\n" + tail)
    framing_marker_case(up, "malformed_chunk_trailers", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer No Colon\r\n\r\n" + tail)
    # #673 review round 8: a colon-only trailer check would have accepted
    # this (colon present, but the name contains a space).
    framing_marker_case(up, "chunk_trailer_colon_but_invalid_name", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Name: x\r\n\r\n" + tail)
    # #673 review round 9: a valid-looking name (no control chars or
    # whitespace) can still contain a non-colon RFC 7230 separator.
    framing_marker_case(up, "chunk_trailer_separator_char_in_name", cat, port, lambda tail:
                         b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad(Name: x\r\n\r\n" + tail)

    # #673 review round 7 point 3: every case above tests one MALFORMED or
    # ambiguous framing combination and asserts it is rejected (zero
    # upstream hits). None of them prove the ordinary, single, valid
    # Content-Length path correctly finds the body boundary in the first
    # place -- the duplicate-CL cases exercise the *rejection* path, not the
    # normal CL boundary computation. Append a pipelined marker request
    # right after a single valid `Content-Length: 4` request's 4-byte body,
    # on the same connection, and assert the first request's body is read
    # as EXACTLY those 4 bytes -- neither over-reading into the marker's
    # bytes (which a boundary off-by-one would do) nor under-reading (which
    # would leave stray bytes to desync the connection). This build of
    # Tardigrade does not eagerly process a second pipelined request already
    # sitting in the same read behind the first (confirmed against a bare
    # double-pipelined GET /health, unrelated to any change in this PR), so
    # this asserts the boundary is exact rather than that the marker itself
    # gets independently dispatched.
    up.reset()
    single_cl_case = "single_cl_boundary"
    single_cl_marker_path = f"/f06-marker-{single_cl_case}"
    single_cl_raw = (
        b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() +
        b"\r\nContent-Length: 4\r\n\r\nABCD" +
        f"GET {single_cl_marker_path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
    )
    send_raw(port, single_cl_raw, read_timeout=1.3)
    single_cl_hits = up.hits()
    single_cl_first = next((h for h in single_cl_hits if h["path"] == "/protected"), None)
    single_cl_ok = (
        single_cl_first is not None
        and single_cl_first["body_len"] == 4
        and single_cl_first["body_preview"] == "ABCD"
        and len(single_cl_hits) == 1
    )
    record("single_content_length_correctly_bounds_the_body_exactly", cat, single_cl_ok,
           f"hits={[(h['path'], h['body_len']) for h in single_cl_hits]}")

    # Truncation-only cases: the connection is deliberately cut short before
    # a complete request exists, so no coherent trailing marker request
    # could ever be appended -- the smuggling oracle above does not apply.
    # These stay as "never dispatches" assertions on the incomplete send.
    up.reset()
    send_raw_then_close_early(port,
                               b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nContent-Length: 100\r\n\r\n",
                               b"short-body-only", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("content_length_longer_than_delivered_body_never_dispatches", cat, ok, f"hits={len(hits)}")

    up.reset()
    send_raw_then_close_early(port,
                               b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
                               b"", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("truncated_chunk_body_never_dispatches", cat, ok, f"hits={len(hits)}")

    up.reset()
    send_raw_then_close_early(port,
                               b"POST /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + VALID_TOKEN.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n",
                               b"", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("missing_final_zero_chunk_never_dispatches", cat, ok, f"hits={len(hits)}")

    up.reset()
    followup = send_raw(port, req("GET", "/health", []))
    ok = b"200" in followup[:20]
    record("connection_healthy_after_smuggling_probes", cat, ok, f"resp={followup[:60]!r}")


def run_header_syntax(up: Upstream, port: int) -> None:
    cat = "framing.request_header_syntax"

    assert_denied(up, "obs_fold_header_continuation", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Custom: value\r\n continued\r\n\r\n")
    assert_denied(up, "nul_byte_in_header_value", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Custom: bad\x00value\r\n\r\n")
    assert_denied(up, "ctl_byte_in_header_name", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Bad\x01Name: value\r\n\r\n")

    # General bare-LF / CR-without-LF parser syntax abuse, distinct from the
    # Authorization-value-specific cases in run_auth_matrix() (#673 review).
    assert_denied(up, "bare_lf_line_terminator_in_headers", cat, port,
                  b"GET /protected HTTP/1.1\nHost: localhost\nX-Custom: value\n\n")
    assert_denied(up, "bare_cr_without_lf_in_header_value", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Custom: val\rue-with-bare-cr\r\n\r\n")

    long_path = "/protected/" + ("a" * 9000)
    assert_denied(up, "oversized_request_line", cat, port,
                  f"GET {long_path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())

    assert_denied(up, "malformed_http_version", cat, port,
                  b"GET /protected HTTP/9.9\r\nHost: localhost\r\n\r\n")
    assert_denied(up, "invalid_method_token", cat, port,
                  b"FOO$BAR /protected HTTP/1.1\r\nHost: localhost\r\n\r\n")

    oversized_value = "x" * 9000
    assert_denied(up, "oversized_single_header", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Big: {oversized_value}\r\n\r\n".encode())

    many_headers = "".join(f"X-H{i}: v\r\n" for i in range(150))
    assert_denied(up, "header_count_over_limit", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\n{many_headers}\r\n".encode())

    aggregate = "".join(f"X-Pad{i}: {'p' * 300}\r\n" for i in range(120))
    assert_denied(up, "aggregate_header_size_over_limit", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\n{aggregate}\r\n".encode())

    assert_denied(up, "missing_host_header_http11", cat, port,
                  b"GET /protected HTTP/1.1\r\n\r\n")

    up.reset()
    raw = send_raw(port, b"TRACE /protected HTTP/1.1\r\nHost: localhost\r\n\r\n")
    status = first_status_code(raw)
    hits = up.hits()
    ok = status == 405 and len(hits) == 0
    record("trace_method_globally_405", cat, ok, f"status={status} hits={len(hits)}")


def run_traversal_boundary(up: Upstream, port: int) -> None:
    cat = "static.traversal_boundary"
    variants = [
        ("dotdot_segment", "/../f06_secret_outside_root.txt"),
        ("percent_encoded_dotdot", "/%2e%2e/f06_secret_outside_root.txt"),
        ("double_percent_encoded_dotdot", "/%252e%252e/f06_secret_outside_root.txt"),
        ("encoded_slash_dotdot", "/..%2ff06_secret_outside_root.txt"),
        ("backslash_dotdot", "/..\\f06_secret_outside_root.txt"),
    ]
    for name, path in variants:
        up.reset()
        raw = send_raw(port, req("GET", path, []))
        status = first_status_code(raw)
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        canary_leaked = TRAVERSAL_CANARY.encode() in body
        ok = not canary_leaked
        record(name, cat, ok, f"status={status} canary_leaked={canary_leaked}")

    # Symlink escape: tests/security/fixtures/f06_static_root/escape-symlink
    # points at ../f06_secret_outside_root.txt (outside the doc root).
    up.reset()
    raw = send_raw(port, req("GET", "/escape-symlink", []))
    status = first_status_code(raw)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    canary_leaked = TRAVERSAL_CANARY.encode() in body
    record("symlink_escape_outside_doc_root", cat, not canary_leaked,
           f"status={status} canary_leaked={canary_leaked}")

    # root/alias interaction: /alias/ is served via `alias`, a different
    # root than the default static location -- confirm it serves its own
    # content and still enforces the same traversal boundary.
    up.reset()
    raw = send_raw(port, req("GET", "/alias/index.html", []))
    status = first_status_code(raw)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    ok = status == 200 and ALIAS_ROOT_CANARY.encode() in body
    record("alias_root_serves_its_own_content", cat, ok, f"status={status}")

    up.reset()
    raw = send_raw(port, req("GET", "/alias/../f06_secret_outside_root.txt", []))
    status = first_status_code(raw)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    canary_leaked = TRAVERSAL_CANARY.encode() in body
    record("alias_root_traversal_boundary_holds", cat, not canary_leaked,
           f"status={status} canary_leaked={canary_leaked}")


def hostile_delayed_ghost_does_not_poison_pool(
    up: Upstream, cat: str, port: int, path: str, name: str, scenario: str = DELAYED_GHOST_SCENARIO
) -> None:
    """
    #673 review: a hostile upstream can send just a bodiless response's
    headers, flush, and only send an illegal body / full ghost response
    AFTER Tardigrade has already decided the connection is idle and
    returned it to the upstream connection pool -- those delayed bytes
    would then poison whatever unrelated request checks the connection out
    next. `parseBufferedUpstreamResponse()`'s in-memory truncation fix
    cannot catch this by itself; it requires bodiless responses to never be
    pooled for reuse at all (verified directly in gateway_proxy.zig; this
    is the live, timing-based confirmation). Parameterized by `path` so it
    can be run against both the buffered and forced-streaming hostile
    routes, which have separate implementations of this fix.

    `scenario` defaults to the bodiless-response variant; round 7 point 5
    also passes `DELAYED_GHOST_AFTER_CONTENT_LENGTH_SCENARIO` /
    `DELAYED_GHOST_AFTER_CHUNKED_SCENARIO`, where the FIRST response is a
    complete, correctly-framed, non-bodiless response that Tardigrade has
    every reason to pool -- proving the ghost is still caught by
    `UpstreamPool.checkout()`'s staleness probe at the next checkout, not
    just by the bodiless-never-reusable rule the original scenario exercises.
    """
    up.reset()
    first = send_raw(port, req("GET", path, [("X-F06-Scenario", scenario)]), read_timeout=0.6)
    # Give the fixture's delayed tail write time to land on the upstream
    # socket before probing -- comfortably longer than its own delay.
    time.sleep(DELAYED_GHOST_DELAY_SECONDS * 2)
    leaked_followup = False
    for _ in range(5):
        followup = send_raw(port, req("GET", path, [("X-F06-Scenario", "")]), read_timeout=1.0)
        if GHOST_MARKER.encode() in followup:
            leaked_followup = True
            break
    leaked_first = GHOST_MARKER.encode() in first
    ok = not leaked_first and not leaked_followup
    record(name, cat, ok, f"leaked_first={leaked_first} leaked_followup={leaked_followup}")


def hostile_1xx_chain_returns_final_response(up: Upstream, cat: str, port: int, path: str, name: str) -> None:
    """
    #673 review: Tardigrade must consume 1xx interim responses instead of
    wrongly treating the first one as final. Asserts the client-visible
    result directly: exactly the real final response, not a bare 103 with
    the 200 silently dropped. Parameterized by `path` so it can be run
    against both the buffered and forced-streaming hostile routes, which
    have separate implementations of this fix.
    """
    up.reset()
    raw = send_raw(port, req("GET", path, [("X-F06-Scenario", "unusual_1xx_chain")]))
    status = first_status_code(raw)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    # The streaming path forwards a chunked body ("2\r\nok\r\n0\r\n\r\n")
    # rather than a Content-Length-framed one; accept either encoding of
    # the same two-byte payload.
    ok = status == 200 and (body == b"ok" or body.endswith(b"2\r\nok\r\n0\r\n\r\n"))
    record(name, cat, ok, f"status={status} body={body!r}")


def run_malicious_upstream(up: Upstream, port: int) -> None:
    cat = "upstream.malicious_response_framing"

    def hostile(scenario: str, path: str = "/hostile") -> bytes:
        return req("GET", path, [("X-F06-Scenario", scenario)])

    core_scenarios = [
        "duplicate_cl_equal",
        "conflicting_cl",
        "reverse_conflicting_cl",
        "te_and_cl",
        "malformed_status_line",
        "ctl_and_bare_cr_in_header_value",
        "truncated_body",
        # #673 review round 5: TE strictness, chunk-terminator validation,
        # and outright 101 rejection.
        "te_list_not_exactly_chunked",
        "duplicate_te",
        "chunk_not_crlf_terminated",
        "upgrade_101_attempt",
        # #673 review round 6: RFC 9110 §15 status-code range enforcement.
        "status_code_too_low",
        "status_code_too_high",
        # #673 review round 8: trailer lines must be valid header-field
        # syntax, not merely "contain a colon somewhere".
        "chunk_trailer_invalid_name",
        # #673 review round 9: a valid-looking name (no control chars or
        # whitespace) can still contain a non-colon RFC 7230 separator.
        "chunk_trailer_separator_char_in_name",
    ]
    for scenario in core_scenarios:
        up.reset()
        raw = send_raw(port, hostile(scenario))
        status = first_status_code(raw)
        followup = send_raw(port, req("GET", "/health", []))
        followup_ok = first_status_code(followup) == 200
        record(f"hostile_upstream_{scenario}_does_not_hang_or_break_edge", cat, followup_ok,
               f"status={status} followup_status={first_status_code(followup)}")

        # Same-downstream-connection desync proof (#673 review point 5):
        # exercised on the SAME socket as the hostile probe, not a fresh
        # connection, so a corrupted response boundary would show up here
        # even if a brand-new connection would look fine.
        hostile_same_socket_reuse(up, f"hostile_upstream_{scenario}_same_connection_reuse_is_clean", cat, port, scenario)

    up.reset()
    raw = send_raw(port, hostile("ctl_and_bare_cr_in_header_value"))
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    sanitized = b"\x00" not in raw and b"with-ctl-and-bare-cr" not in raw
    record("hostile_upstream_ctl_bare_cr_not_reflected_verbatim", cat, sanitized,
           f"resp_head={raw[:200]!r}")

    # RFC 7230 §6.1 hop-by-hop headers and technology-disclosure headers a
    # hostile upstream might try to ride through verbatim; each must be
    # stripped before the client sees it.
    stripped_header_scenarios = [
        ("connection_custom_hop", "x-hostile-secret"),
        ("proxy_connection_header", "proxy-connection"),
        ("te_header", "te"),
        ("trailer_header", "trailer"),
        ("upgrade_header", "upgrade"),
        # A bare LF hiding a Connection nomination behind what a naive
        # scanner treats as reason-phrase text (#673 review) -- composes
        # the malformed-status-line and Connection-nomination cases.
        ("bare_lf_hides_connection_nomination", "x-hostile-secret"),
    ]
    for scenario, header_name in stripped_header_scenarios:
        up.reset()
        raw = send_raw(port, hostile(scenario))
        headers = response_headers_lower(raw)
        ok = header_name not in headers
        record(f"hostile_upstream_{scenario}_stripped", cat, ok, f"headers={list(headers.keys())}")

    up.reset()
    raw = send_raw(port, hostile("server_header"))
    headers = response_headers_lower(raw)
    ok = headers.get("server") == "tardigrade"
    record("hostile_upstream_server_header_replaced_not_leaked", cat, ok, f"server={headers.get('server')!r}")

    up.reset()
    raw = send_raw(port, hostile("x_powered_by_header"))
    headers = response_headers_lower(raw)
    ok = "x-powered-by" not in headers
    record("hostile_upstream_x_powered_by_stripped", cat, ok, f"headers={list(headers.keys())}")

    up.reset()
    first = send_raw(port, hostile("extra_bytes_after_response"))
    followup = send_raw(port, hostile(""))
    # #673 review point 3: the ghost marker must be checked against the
    # FIRST response too, not just the follow-up -- a prior version of this
    # test discarded `first` entirely, so a Tardigrade bug that immediately
    # forwarded the ghost bytes as part of its own first response would
    # have passed silently.
    leaked_first = GHOST_MARKER.encode() in first
    leaked_followup = GHOST_MARKER.encode() in followup
    ok = not leaked_first and not leaked_followup
    record("hostile_upstream_extra_bytes_do_not_leak_into_next_response", cat, ok,
           f"leaked_first={leaked_first} leaked_followup={leaked_followup} followup_head={followup[:100]!r}")
    hostile_same_socket_reuse(up, "hostile_upstream_extra_bytes_same_connection_reuse_is_clean", cat, port, "extra_bytes_after_response")

    # The chunked-framing twin of the above (#673 review round 5): a ghost
    # response appended right after a chunked body's "0\r\n\r\n" terminator
    # must not leak into either the first response or a later one over a
    # reused connection.
    up.reset()
    first = send_raw(port, hostile("chunked_extra_bytes_after_terminator"))
    followup = send_raw(port, hostile(""))
    leaked_first = GHOST_MARKER.encode() in first
    leaked_followup = GHOST_MARKER.encode() in followup
    ok = not leaked_first and not leaked_followup
    record("hostile_upstream_chunked_extra_bytes_do_not_leak_into_next_response", cat, ok,
           f"leaked_first={leaked_first} leaked_followup={leaked_followup} followup_head={followup[:100]!r}")
    hostile_same_socket_reuse(up, "hostile_upstream_chunked_extra_bytes_same_connection_reuse_is_clean",
                               cat, port, "chunked_extra_bytes_after_terminator")

    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile",
                                                "hostile_upstream_delayed_ghost_after_bodiless_does_not_poison_pool")
    # #673 review round 7 point 5: unlike the bodiless case above, these two
    # responses land exactly on their declared boundary and are legitimately
    # pooled -- proving the ghost is caught by UpstreamPool.checkout()'s
    # staleness probe at the NEXT checkout, not just by bodiless responses
    # never being reusable in the first place.
    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile",
                                                "hostile_upstream_delayed_ghost_after_content_length_does_not_poison_pool",
                                                scenario=DELAYED_GHOST_AFTER_CONTENT_LENGTH_SCENARIO)
    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile",
                                                "hostile_upstream_delayed_ghost_after_chunked_does_not_poison_pool",
                                                scenario=DELAYED_GHOST_AFTER_CHUNKED_SCENARIO)
    hostile_1xx_chain_returns_final_response(up, cat, port, "/hostile",
                                              "hostile_upstream_unusual_1xx_chain_returns_actual_final_response")

    for scenario in ["unusual_1xx_chain", "invalid_204_with_body", "invalid_304_with_body"]:
        up.reset()
        _ = send_raw(port, hostile(scenario))
        followup = send_raw(port, req("GET", "/health", []))
        ok = first_status_code(followup) == 200
        record(f"hostile_upstream_{scenario}_connection_stays_healthy", cat, ok,
               f"followup_status={first_status_code(followup)}")
        hostile_same_socket_reuse(up, f"hostile_upstream_{scenario}_same_connection_reuse_is_clean", cat, port, scenario)

    # #673 review: the streaming proxy path (streamProxyOverTransport /
    # readUpstreamHead) has its own, separately-fixed copies of the
    # bodiless-reuse and 1xx-interim logic. Streaming is off by default, so
    # the whole campaign above -- run against /hostile -- only ever
    # exercised the buffered path. Replay the two scenarios the review
    # specifically called out against /hostile-streaming, a forced-streaming
    # twin of the same upstream route (see f06_tardigrade.conf).
    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile-streaming",
                                                "hostile_upstream_streaming_delayed_ghost_after_bodiless_does_not_poison_pool")
    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile-streaming",
                                                "hostile_upstream_streaming_delayed_ghost_after_content_length_does_not_poison_pool",
                                                scenario=DELAYED_GHOST_AFTER_CONTENT_LENGTH_SCENARIO)
    hostile_delayed_ghost_does_not_poison_pool(up, cat, port, "/hostile-streaming",
                                                "hostile_upstream_streaming_delayed_ghost_after_chunked_does_not_poison_pool",
                                                scenario=DELAYED_GHOST_AFTER_CHUNKED_SCENARIO)
    hostile_1xx_chain_returns_final_response(up, cat, port, "/hostile-streaming",
                                              "hostile_upstream_streaming_unusual_1xx_chain_returns_actual_final_response")

    # #673 review round 7 point 4: a hostile origin drip-feeding interim
    # responses forever must not tie up the streaming path indefinitely.
    # Buffered-path 1xx handling is already bounded by the total-bytes cap
    # on the response buffer regardless of iteration count, so this is
    # streaming-only.
    #
    # The response itself (a 502, once the cap rejects the chain) arrives in
    # a few milliseconds, but Tardigrade does not force-close the downstream
    # connection just because the upstream exchange failed -- so `send_raw`
    # always runs its full read_timeout waiting for an EOF that never comes,
    # regardless of how fast the response was. Elapsed time through
    # `send_raw` is therefore not a usable "did this hang" signal here; a
    # real hang (no cap, chain never ends) would instead show up as no
    # status line at all having arrived by the time that timeout elapses.
    up.reset()
    raw = send_raw(port, hostile("excessive_1xx_chain", "/hostile-streaming"), read_timeout=1.2)
    followup = send_raw(port, req("GET", "/health", []))
    got_a_response = first_status_code(raw) is not None
    edge_healthy = first_status_code(followup) == 200
    ok = got_a_response and edge_healthy
    record("hostile_upstream_streaming_excessive_1xx_chain_does_not_hang_or_break_edge", cat, ok,
           f"status={first_status_code(raw)} followup_status={first_status_code(followup)}")

    up.reset()
    raw = send_raw(port, hostile("reverse_conflicting_cl", "/hostile-streaming"))
    followup = send_raw(port, req("GET", "/health", []))
    ok = first_status_code(followup) == 200
    record("hostile_upstream_streaming_reverse_conflicting_cl_does_not_hang_or_break_edge", cat, ok,
           f"status={first_status_code(raw)} followup_status={first_status_code(followup)}")
    hostile_same_socket_reuse(up, "hostile_upstream_streaming_reverse_conflicting_cl_same_connection_reuse_is_clean",
                               cat, port, "reverse_conflicting_cl", path="/hostile-streaming")

    up.reset()
    raw = send_raw(port, hostile("bare_lf_hides_connection_nomination", "/hostile-streaming"))
    headers = response_headers_lower(raw)
    ok = "x-hostile-secret" not in headers
    record("hostile_upstream_streaming_bare_lf_hides_connection_nomination_stripped", cat, ok,
           f"status={first_status_code(raw)} headers={list(headers.keys())}")

    # #673 review round 5: TE strictness and 101 rejection both live in
    # `detectResponseFraming`, which `readUpstreamHead` (streaming) now
    # shares with the buffered path via `parseStrictStatusLine` -- replay a
    # representative pair against /hostile-streaming to prove the fix
    # actually reaches this path too, not just the buffered one the rest of
    # this suite exercises by default.
    # #673 review round 8: consumeChunkTrailers() (streaming) is a separate
    # implementation from the buffered decoder's trailer validation and had
    # no validation at all before this round -- replay against
    # /hostile-streaming to prove the fix reaches this path too.
    for scenario in [
        "duplicate_te",
        "upgrade_101_attempt",
        "status_code_too_low",
        "status_code_too_high",
        "chunk_trailer_invalid_name",
        "chunk_trailer_separator_char_in_name",
    ]:
        up.reset()
        raw = send_raw(port, hostile(scenario, "/hostile-streaming"))
        followup = send_raw(port, req("GET", "/health", []))
        ok = first_status_code(followup) == 200
        record(f"hostile_upstream_streaming_{scenario}_does_not_hang_or_break_edge", cat, ok,
               f"status={first_status_code(raw)} followup_status={first_status_code(followup)}")
        hostile_same_socket_reuse(up, f"hostile_upstream_streaming_{scenario}_same_connection_reuse_is_clean",
                                   cat, port, scenario, path="/hostile-streaming")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tardi-port", type=int, default=18089)
    parser.add_argument("--upstream-port", type=int, default=18189)
    parser.add_argument("--evidence-json", default=None)
    args = parser.parse_args()

    up = Upstream(args.upstream_port)
    port = args.tardi_port

    run_auth_matrix(up, port)
    run_identity_spoofing(up, port)
    run_method_change_bypass(up, port)
    run_path_canonicalization(up, port)
    run_positive_control_and_replay(up, port)
    run_hostile_framing(up, port)
    run_header_syntax(up, port)
    run_traversal_boundary(up, port)
    run_malicious_upstream(up, port)

    total = len(RESULTS)
    failed = [r for r in RESULTS if not r.ok]
    print(f"\n{total - len(failed)}/{total} cases passed")
    if failed:
        print("\nFAILURES:")
        for r in failed:
            print(f"  - [{r.category}] {r.name}: {r.detail}")

    if args.evidence_json:
        with open(args.evidence_json, "w") as f:
            json.dump(
                {
                    "total": total,
                    "passed": total - len(failed),
                    "failed": [{"name": r.name, "category": r.category, "detail": r.detail} for r in failed],
                    "results": [{"name": r.name, "category": r.category, "ok": r.ok, "detail": r.detail} for r in RESULTS],
                },
                f,
                indent=2,
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
