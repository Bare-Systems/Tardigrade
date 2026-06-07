import http from 'k6/http';

// Fixed-length upload scenario for reverse-proxy streaming benchmarks.
//
// Env vars:
//   BASE_URL       target base URL
//   UPLOAD_PATH    proxied upload path
//   UPLOAD_BYTES   request body size
//   K6_HOST_HEADER optional Host header
//   K6_VUS         virtual users
//   K6_DURATION    test duration

const baseUrl = __ENV.BASE_URL || 'http://127.0.0.1:8069';
const target = `${baseUrl}${__ENV.UPLOAD_PATH || '/proxy/upload-large'}`;
const uploadBytes = parseInt(__ENV.UPLOAD_BYTES || '1048576');
const payload = 'u'.repeat(uploadBytes);
const headers = {
  'Content-Type': 'application/octet-stream',
};
if (__ENV.K6_HOST_HEADER) {
  headers.Host = __ENV.K6_HOST_HEADER;
}

export const options = {
  vus: parseInt(__ENV.K6_VUS || '20'),
  duration: __ENV.K6_DURATION || '30s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'p(99.9)'],
  noConnectionReuse: false,
};

export default function () {
  http.post(target, payload, { headers });
}
