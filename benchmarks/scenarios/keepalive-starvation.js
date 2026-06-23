import http from 'k6/http';
import { sleep } from 'k6';
import { Trend } from 'k6/metrics';

// Keepalive starvation scenario (#204).
//
// Measures that a large pool of idle keepalive clients does not starve workers
// handling fresh active requests. Two VU groups run in parallel:
//
//   idle-holders  — hold open keepalive connections with a very slow request
//                   rate (one request per IDLE_SLEEP_S seconds). These simulate
//                   parked connections that used to occupy worker threads.
//
//   active-burst  — fire requests as fast as possible on new connections.
//                   Their p99 latency is the starvation signal: under the old
//                   blocking model, active requests would queue behind the idle
//                   holders once all workers were occupied.
//
// Env vars (set by run.sh or the operator):
//   BASE_URL            target URL base  (default: http://127.0.0.1:8069)
//   K6_TARGET_PATH      request path     (default: /health)
//   K6_HOST_HEADER      optional Host header override
//   K6_DURATION         test duration    (default: 30s)
//   IDLE_VUS            number of idle keepalive holders (default: 20)
//   ACTIVE_VUS          number of active request VUs    (default: 10)
//   IDLE_SLEEP_S        seconds between idle-holder requests (default: 10)

const baseUrl = __ENV.BASE_URL || 'http://127.0.0.1:8069';
const targetPath = __ENV.K6_TARGET_PATH || '/health';
const target = `${baseUrl}${targetPath}`;
const params = __ENV.K6_HOST_HEADER ? { headers: { Host: __ENV.K6_HOST_HEADER } } : undefined;

const idleVUs = parseInt(__ENV.IDLE_VUS || '20');
const activeVUs = parseInt(__ENV.ACTIVE_VUS || '10');
const idleSleepS = parseFloat(__ENV.IDLE_SLEEP_S || '10');

const activeTrend = new Trend('active_request_duration', true);

export const options = {
  scenarios: {
    idle_holders: {
      executor: 'constant-vus',
      vus: idleVUs,
      duration: __ENV.K6_DURATION || '30s',
      exec: 'idleHolder',
    },
    active_burst: {
      executor: 'constant-vus',
      vus: activeVUs,
      duration: __ENV.K6_DURATION || '30s',
      exec: 'activeBurst',
    },
  },
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'p(99.9)'],
  noConnectionReuse: false,
};

// Idle holder: keeps a keepalive connection open with a very low request rate.
export function idleHolder() {
  http.get(target, params);
  sleep(idleSleepS);
}

// Active burst: fires requests as fast as possible from its own connection.
// Its p99 is the starvation signal.
export function activeBurst() {
  const start = Date.now();
  http.get(target, params);
  activeTrend.add(Date.now() - start);
}
