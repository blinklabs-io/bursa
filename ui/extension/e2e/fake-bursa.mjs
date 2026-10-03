import { createServer } from 'node:http';

// The real service treats a bare ID as a Chromium extension ID.
const normalize = (id) => (id.includes('://') ? id : `chrome-extension://${id}`);

export const PAIRING_CODE = '123456';
export const TOKEN = 'e2e-token';

// A stand-in for the Bursa connector endpoints with the same observable rules the
// extension depends on: no CORS headers until paired, the token must accompany the
// paired extension's Origin, and every dApp origin needs its own enable() grant.
export class FakeBursa {
  paired = null;
  grants = new Set();
  rejectEnable = false;
  requests = [];
  #server = createServer((request, response) => this.#handle(request, response));
  #port = 0;

  get port() {
    return this.#port;
  }

  async start() {
    await new Promise((resolve, reject) => {
      this.#server.once('error', reject);
      this.#server.listen(this.#port, '127.0.0.1', resolve);
    });
    this.#port = this.#server.address().port;
  }

  async stop() {
    await new Promise((resolve) => this.#server.close(resolve));
    this.#server = createServer((request, response) => this.#handle(request, response));
  }

  #handle(request, response) {
    let raw = '';
    request.on('data', (chunk) => (raw += chunk));
    request.on('end', () => {
      const send = (status, body) => {
        const headers = { 'Content-Type': 'application/json' };
        if (this.paired) {
          headers['Access-Control-Allow-Origin'] = this.paired;
          headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Bursa-Token';
        }
        response.writeHead(status, headers);
        response.end(JSON.stringify(body));
      };
      if (request.method === 'OPTIONS') return send(204, {});
      const body = raw ? JSON.parse(raw) : {};

      if (request.url === '/connector/pair') {
        if (!body.code) {
          this.pending = normalize(body.extension_id);
          return send(202, { status: 'pending' });
        }
        if (body.code !== PAIRING_CODE || normalize(body.extension_id) !== this.pending) {
          return send(403, { error: 'pairing code mismatch' });
        }
        this.paired = this.pending;
        return send(200, { token: TOKEN });
      }

      if (
        request.url !== '/connector/request' ||
        request.headers['x-bursa-token'] !== TOKEN ||
        request.headers.origin !== this.paired
      ) {
        return send(401, { error: 'unauthorized' });
      }
      this.requests.push({ origin: body.origin, method: body.method });
      if (body.method === 'isEnabled') return send(200, { result: this.grants.has(body.origin) });
      if (body.method === 'enable') {
        if (this.rejectEnable) return send(403, { error_code: -3, info: 'user declined' });
        this.grants.add(body.origin);
        return send(200, { result: null });
      }
      if (!this.grants.has(body.origin)) {
        return send(403, { error_code: -3, info: 'origin not granted' });
      }
      return send(200, { result: 0 });
    });
  }
}
