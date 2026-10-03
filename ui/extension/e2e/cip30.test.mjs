// Usage: node e2e/cip30.test.mjs chrome|firefox   (after `npm run build`)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, launchFirefox } from './browsers.mjs';
import { FakeBursa, PAIRING_CODE } from './fake-bursa.mjs';

const target = process.argv[2];
assert.ok(['chrome', 'firefox'].includes(target), 'usage: cip30.test.mjs chrome|firefox');

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist');
const { version } = JSON.parse(readFileSync(resolve(root, 'manifest.json'), 'utf8'));
const pageServer = createServer((request, response) => {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  let body = '<!doctype html><title>page</title>';
  if (request.url === '/csp') {
    headers['Content-Security-Policy'] =
      "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'";
  } else {
    // Runs inline before any later script, so it sees only what document_start scripts registered.
    body += '<script>window.__atStart = Boolean(window.cardano && window.cardano.bursa);</script>';
  }
  response.writeHead(200, headers);
  response.end(body);
});
await new Promise((resolveListen) => pageServer.listen(0, '127.0.0.1', resolveListen));
const pagePort = pageServer.address().port;
// Distinct loopback hostnames are distinct web origins.
const originA = `http://127.0.0.1:${pagePort}`;
const originB = `http://localhost:${pagePort}`;

async function eventually(page, expression, what) {
  for (let i = 0; i < 100; i++) {
    const { ok } = await page.run(`return ${expression};`);
    if (ok) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  const diag = await page.run('return [document.body.innerText, document.getElementById("port-input").value, String(typeof chrome), Array.from(document.scripts).map(s=>s.src)];');
  assert.fail(`timed out waiting for ${what}: ${JSON.stringify(diag)}`);
}

const bursa = new FakeBursa();
await bursa.start();
const browser =
  target === 'chrome'
    ? await launchChrome(resolve(dist, 'chrome'))
    : await launchFirefox(resolve(dist, `bursa-connector-firefox-${version}.zip`));

try {
  // Provider registration happens at document_start, also under a restrictive CSP.
  const early = await browser.open(`${originA}/early`);
  assert.deepEqual(await early.run('return window.__atStart;'), { ok: true });
  await early.close();
  const csp = await browser.open(`${originA}/csp`);
  assert.deepEqual(await csp.run('return window.cardano.bursa.name;'), { ok: 'Bursa' });
  assert.deepEqual(await csp.run('return typeof (window.chrome && window.chrome.storage);'), {
    ok: 'undefined',
  });
  await csp.close();

  const pageA = await browser.open(`${originA}/early`);
  const pageB = await browser.open(`${originB}/early`);
  const call = (page, method) => page.run(`return window.cardano.bursa.${method};`);

  // Not paired yet.
  let result = await call(pageA, 'enable()');
  assert.equal(result.err?.code, -3, JSON.stringify(result));
  assert.match(result.err.info, /Not paired/);

  // Pair through the popup, then confirm the token survives a popup reload.
  const popup = await browser.open(`${browser.origin}/popup.html`);
  // The popup fills the port field once its storage read resolves, so keep setting it.
  await eventually(
    popup,
    `(() => {
      document.getElementById('port-input').value = '${bursa.port}';
      document.getElementById('pair-btn').click();
      return !document.getElementById('code-section').hidden;
    })()`,
    'the code prompt',
  );
  await popup.run(`
    document.getElementById('code-input').value = '${PAIRING_CODE}';
    document.getElementById('confirm-btn').click();`);
  await eventually(
    popup,
    `document.getElementById('status-bar').textContent === 'Connected'`,
    'the paired status',
  );
  await popup.close();
  const reopened = await browser.open(`${browser.origin}/popup.html`);
  await eventually(
    reopened,
    `document.getElementById('status-bar').textContent === 'Connected'`,
    'the persisted pairing',
  );
  await reopened.close();
  assert.equal(bursa.paired, browser.origin);

  // enable() approval, then a CIP-30 call.
  assert.deepEqual(await call(pageA, 'isEnabled()'), { ok: false });
  assert.deepEqual(await call(pageA, 'enable().then(() => true)'), { ok: true });
  assert.deepEqual(await call(pageA, 'isEnabled()'), { ok: true });
  assert.deepEqual(await call(pageA, 'enable().then((api) => api.getNetworkId())'), { ok: 0 });
  assert.ok(
    bursa.requests.every((r) => r.origin === originA),
    `backend must see the browser-verified origin: ${JSON.stringify(bursa.requests)}`,
  );

  // A grant for one origin is not reused by another, and a rejected approval stays rejected.
  assert.deepEqual(await call(pageB, 'isEnabled()'), { ok: false });
  bursa.rejectEnable = true;
  assert.deepEqual(await call(pageB, 'enable()'), { err: { code: -3, info: 'user declined' } });
  bursa.rejectEnable = false;
  assert.deepEqual(await call(pageB, 'isEnabled()'), { ok: false });
  assert.deepEqual([...bursa.grants], [originA]);

  // An unreachable Bursa backend is reported, not hung.
  await bursa.stop();
  result = await call(pageA, 'isEnabled()');
  assert.equal(result.err?.code, -2, JSON.stringify(result));
  await bursa.start();

  // The background is suspended; the persisted pairing still serves the next request.
  await browser.suspendBackground();
  assert.deepEqual(await call(pageA, 'enable().then((api) => api.getNetworkId())'), { ok: 0 });
  assert.equal(bursa.paired, browser.origin);
} finally {
  await browser.close();
  await bursa.stop().catch(() => undefined);
  await new Promise((resolveClose) => pageServer.close(resolveClose));
}
console.log(`${target}: ok`);
