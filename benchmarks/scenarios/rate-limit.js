import http from 'k6/http';
import { check, sleep } from 'k6';

// Rate-limit correctness scenario — verifies that Tardigrade actually enforces its
// per-descriptor token-bucket limit rather than merely slowing responses.
//
// Strategy: a single VU fires requests as fast as possible for long enough to
// guarantee it exceeds RATE_LIMIT_RPS. We then assert that at least some
// responses were 429 Too Many Requests.
//
// Env vars:
//   BASE_URL          target base URL        (default: http://127.0.0.1:8069)
//   K6_HOST_HEADER    optional Host header / :authority override
//   RATE_LIMIT_RPS    configured RPS ceiling (default: 10 — matches Tardigrade default)
//   RATE_LIMIT_PATH   path to hammer         (default: /health)
//   K6_DURATION       test duration          (default: 15s)

const baseUrl       = __ENV.BASE_URL         || 'http://127.0.0.1:8069';
const hostHeader    = __ENV.K6_HOST_HEADER   || '';
const rateLimitRps  = parseInt(__ENV.RATE_LIMIT_RPS  || '10');
const ratePath      = __ENV.RATE_LIMIT_PATH  || '/health';

const targetUrl = `${baseUrl}${ratePath}`;
const params = hostHeader ? { headers: { Host: hostHeader } } : undefined;

// Iterations: enough to comfortably exceed the RPS budget within the duration.
// Single VU so all requests share the same client IP descriptor.
const durationSecs = 15;
const iterations   = rateLimitRps * durationSecs * 3;

export const options = {
  vus:               1,
  iterations:        iterations,
  summaryTrendStats: ['med', 'p(99)'],
  thresholds: {
    // Expect at least 30% of requests to be rate-limited (429)
    'checks{check:rate-limited}': ['rate>0.30'],
  },
};

export default function () {
  const res = http.get(targetUrl, params);
  check(res, { 'rate-limited': (r) => r.status === 429 }, { check: 'rate-limited' });
  // No sleep — fire as fast as possible to hit the limit
}
