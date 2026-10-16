// @vitest-environment node
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, expect, test } from 'vitest';

let server;
let base;
beforeAll(async () => {
  server = spawn(process.execPath, ['design-preview.mjs'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)),
    env: { ...process.env, BURSA_PREVIEW_PORT: '0', BURSA_PREVIEW_SCENARIO: 'vault-create' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  base = await new Promise((resolve, reject) => {
    server.stdout.on('data', (chunk) => {
      const url = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+/);
      if (url) resolve(url[0]);
    });
    server.once('error', reject);
    server.once('exit', (code) => reject(new Error(`Preview exited during startup: ${code}`)));
  });
});
afterAll(async () => {
  if (server && server.exitCode === null) {
    const exited = once(server, 'exit');
    server.kill();
    await exited;
  }
});

test.each(['%', '%E0%A4%A'])('rejects malformed asset URL %s and keeps serving requests', async (unit) => {
  const response = await fetch(`${base}/wallet/assets/${unit}`);
  expect(response.status).toBe(400);
  expect(await response.json()).toEqual({ error: 'Invalid URL.' });
  expect((await fetch(`${base}/status`)).status).toBe(200);
});

test('decodes a valid asset URL once', async () => {
  const response = await fetch(`${base}/wallet/assets/%31${'1'.repeat(55)}4d696e73776170`);
  expect(response.status).toBe(200);
  expect((await response.json()).metadata.ticker).toBe('MIN');
});

test('exercises first-run screens with invalid placeholder words and no persisted vault', async () => {
  const response = await fetch(`${base}/vault`, { method: 'POST', body: '{}' });
  expect(await response.json()).toEqual({ exists: true, locked: false, wallet_count: 0 });
  const phrase = await (await fetch(`${base}/wallet/mnemonic/generate`)).json();
  expect(phrase.mnemonic.split(' ')).toHaveLength(24);
  expect(new Set(phrase.mnemonic.split(' '))).toEqual(new Set(['preview']));
  expect((await (await fetch(`${base}/vault/status`)).json()).exists).toBe(false);
});

test.each([
  ['POST', '/wallet'],
  ['POST', '/wallet/send'],
  ['POST', '/wallet/send/preview-only/confirm'],
  ['PUT', '/wallet/settings/auto-lock'],
])('refuses persistent or transaction writes: %s %s', async (method, path) => {
  const response = await fetch(`${base}${path}`, { method, body: '{}' });
  expect(response.status).toBe(403);
});
