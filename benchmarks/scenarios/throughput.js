import http from 'k6/http';
import { sleep } from 'k6';

// Generic throughput scenario. Used by static-http1, proxy-http1, and keepalive
// runs when k6 is the selected tool in benchmarks/run.sh.
//
// Env vars (set by run.sh):
//   BASE_URL      target URL  (default: http://127.0.0.1:8069/health)
//   K6_VUS        virtual users  (default: 50)
//   K6_DURATION   test duration  (default: 30s)

const baseUrl = __ENV.BASE_URL || 'http://127.0.0.1:8069';
const target  = __ENV.K6_TARGET_PATH ? `${baseUrl}${__ENV.K6_TARGET_PATH}` : `${baseUrl}/health`;

export const options = {
  vus:                parseInt(__ENV.K6_VUS      || '50'),
  duration:           __ENV.K6_DURATION           || '30s',
  summaryTrendStats:  ['med', 'p(99)'],
  noConnectionReuse:  false,
};

export default function () {
  http.get(target);
  // no sleep — maximise request rate to match wrk/h2load/fortio behaviour
}
