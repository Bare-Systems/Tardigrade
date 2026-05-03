import http from 'k6/http';
import { sleep } from 'k6';

// Treat 4xx (including 429 rate-limit responses) as expected so the error-rate
// threshold only fires on genuine server faults (5xx) or network failures.
// Run with TARDIGRADE_RATE_LIMIT_RPS=0 for a pure throughput spike test.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

// Spike test — verifies Tardigrade stays stable under a sudden surge in traffic.
// Stages: gentle warm-up → spike to peak load → sustain → recovery → ramp-down.
//
// Thresholds are intentionally lenient for a spike scenario; tighten them once
// you have established a baseline on your hardware.
//
// Env vars:
//   BASE_URL      target base URL    (default: http://127.0.0.1:8069)
//   K6_HOST_HEADER  optional Host header / :authority override
//   SPIKE_PEAK    peak VU count      (default: 150)
//   SPIKE_PATH    path to request    (default: /health)

const baseUrl  = __ENV.BASE_URL   || 'http://127.0.0.1:8069';
const hostHeader = __ENV.K6_HOST_HEADER || '';
const peak     = parseInt(__ENV.SPIKE_PEAK || '150');
const path     = __ENV.SPIKE_PATH || '/health';

const targetUrl = `${baseUrl}${path}`;
const params = hostHeader ? { headers: { Host: hostHeader } } : undefined;

export const options = {
  stages: [
    { duration: '10s', target: Math.round(peak * 0.1) }, // warm-up
    { duration: '5s',  target: peak },                   // spike
    { duration: '20s', target: peak },                   // sustain peak
    { duration: '10s', target: Math.round(peak * 0.1) }, // recovery
    { duration: '5s',  target: 0 },                      // ramp-down
  ],
  summaryTrendStats: ['med', 'p(99)'],
  thresholds: {
    'http_req_failed':   ['rate<0.05'],   // <5% errors during spike
    'http_req_duration': ['p(99)<1000'],  // p99 under 1 s even at peak
  },
};

export default function () {
  http.get(targetUrl, params);
  sleep(0.05); // light pacing to avoid starving the OS scheduler
}
