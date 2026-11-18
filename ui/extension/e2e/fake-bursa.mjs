import { createServer } from 'node:http';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

// The real service treats a bare ID as a Chromium extension ID.
const normalize = (id) => (id.includes('://') ? id : `chrome-extension://${id}`);


// A stand-in for the Bursa connector endpoints with the same observable rules the
// extension depends on: no CORS headers until paired, each request carries a
// single-use signed challenge, and every dApp origin needs its own enable() grant.
export class FakeBursa {
  paired = null;
  publicKey = null;
  challenges = new Set();
  issuedProofs = new Map();
  grants = new Set();
  rejectEnable = false;
  requests = [];
  #server = createServer((request, response) => this.#handle(request, response));
  #port = 0;

  get port() {
    return this.#port;
  }

  confirmDesktop(code) {
    const expected = createHash('sha256').update('bursa-pair-v1\n' + this.pendingKey).digest('hex').slice(0, 32);
    if (code !== expected) throw new Error('pairing fingerprint mismatch');
    this.paired = this.pending;
    this.publicKey = createPublicKey({ key: Buffer.from(this.pendingKey, 'base64url'), format: 'der', type: 'spki' });
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
          headers['Access-Control-Allow-Headers'] =
            'Content-Type, X-Bursa-Challenge, X-Bursa-Signature';
        }
        response.writeHead(status, headers);
        response.end(JSON.stringify(body));
      };
      if (request.method === 'OPTIONS') return send(204, {});
      const body = raw ? JSON.parse(raw) : {};

      if (request.url === '/connector/pair') {
        if (body.code) return send(403, { error: 'confirm in desktop wallet' });
        this.pending = normalize(body.extension_id);
        this.pendingKey = body.public_key;
        return send(202, { status: 'pending' });
      }

      if (request.url === '/connector/challenge' && request.headers.origin === this.paired) {
        const challenge = request.headers['x-bursa-challenge'];
        const signature = request.headers['x-bursa-signature'];
        const digest = createHash('sha256').update('').digest('base64url');
        const payload = `bursa-connector-v1\n${challenge}\nPOST\n/connector/challenge\n${digest}`;
        if (!verify('sha256', Buffer.from(payload), { key: this.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature ?? '', 'base64url'))) return send(401, {});
        const prior = this.issuedProofs.get(challenge);
        if (prior) return prior.redeemed ? send(401, {}) : send(200, { challenge: prior.value });
        const value = randomBytes(32).toString('base64url');
        this.issuedProofs.set(challenge, { value, redeemed: false });
        this.challenges.add(value);
        return send(200, { challenge: value });
      }

      const challenge = request.headers['x-bursa-challenge'];
      const signature = request.headers['x-bursa-signature'];
      const bodyDigest = createHash('sha256').update(raw).digest('base64url');
      const payload = `bursa-connector-v1\n${challenge}\n${request.method}\n${request.url}\n${bodyDigest}`;
      const authorized =
        request.url === '/connector/request' &&
        request.headers.origin === this.paired &&
        this.challenges.delete(challenge) &&
        verify(
          'sha256',
          Buffer.from(payload),
          { key: this.publicKey, dsaEncoding: 'ieee-p1363' },
          Buffer.from(signature ?? '', 'base64url'),
        );
      if (!authorized) {
        return send(401, { error: 'unauthorized' });
      }
      for (const proof of this.issuedProofs.values()) {
        if (proof.value === challenge) proof.redeemed = true;
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
