import http from 'k6/http';
import { check } from 'k6';

// Mark 4xx responses as expected so http_req_failed only fires on 5xx / network errors.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

// Auth enforcement scenario — verifies that protected routes reject unauthenticated
// requests and accept valid bearer tokens, both under concurrent load.
//
// Env vars:
//   BASE_URL             target base URL  (default: http://127.0.0.1:8069)
//   K6_HOST_HEADER       optional Host header / :authority override
//   AUTH_TOKEN           valid bearer token for authenticated requests
//   AUTH_PROTECTED_PATH  path that requires auth  (default: /v1/status)
//   K6_VUS               virtual users  (default: 20)
//   K6_DURATION          test duration  (default: 15s)

const baseUrl       = __ENV.BASE_URL             || 'http://127.0.0.1:8069';
const hostHeader    = __ENV.K6_HOST_HEADER       || '';
const protectedPath = __ENV.AUTH_PROTECTED_PATH  || '/v1/status';
const authToken     = __ENV.AUTH_TOKEN           || '';

const protectedUrl = `${baseUrl}${protectedPath}`;
const baseParams = hostHeader ? { headers: { Host: hostHeader } } : {};

// Treat 401 as an expected (non-failure) response so http_req_failed only
// captures genuine errors (5xx, network failures).
export const options = {
  vus:               parseInt(__ENV.K6_VUS || '20'),
  duration:          __ENV.K6_DURATION     || '15s',
  summaryTrendStats: ['med', 'p(99)'],
  thresholds: {
    // Unauthenticated requests must be rejected — virtually all should be 401
    'checks{type:unauth}': ['rate>0.99'],
    // If an auth token is provided, authenticated requests must succeed
    'checks{type:auth}':   ['rate>0.99'],
    // No server errors (5xx) or network failures — 4xx are expected and excluded
    'http_req_failed': ['rate<0.01'],
  },
};

export default function () {
  // Unauthenticated — expect 401
  const unauthRes = http.get(protectedUrl, { ...baseParams, tags: { type: 'unauth' } });
  check(unauthRes, { 'unauthenticated → 401': (r) => r.status === 401 }, { type: 'unauth' });

  // Authenticated — expect 2xx (only runs when a token is supplied)
  if (authToken) {
    const authRes = http.get(protectedUrl, {
      headers: { ...(baseParams.headers || {}), Authorization: `Bearer ${authToken}` },
      tags:    { type: 'auth' },
    });
    check(authRes, { 'authenticated → 2xx': (r) => r.status >= 200 && r.status < 300 }, { type: 'auth' });
  }
}
