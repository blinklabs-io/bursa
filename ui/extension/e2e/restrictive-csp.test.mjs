import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const extensionDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const manifest = JSON.parse(await readFile(join(extensionDir, 'manifest.json'), 'utf8'));
assert.equal(manifest.minimum_chrome_version, '111');
assert.deepEqual(
  manifest.content_scripts.map(({ js, run_at: runAt, world }) => ({ js, runAt, world })),
  [
    { js: ['content.js'], runAt: 'document_start', world: 'ISOLATED' },
    { js: ['injected.js'], runAt: 'document_start', world: 'MAIN' },
  ],
);
assert.equal(manifest.web_accessible_resources, undefined);

const userDataDir = await mkdtemp(join(tmpdir(), 'bursa-extension-e2e-'));
const server = createServer((_request, response) => {
  response.writeHead(200, {
    'Content-Security-Policy':
      "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'",
    'Content-Type': 'text/html; charset=utf-8',
  });
  response.end('<!doctype html><html><head><title>Restrictive CSP</title></head></html>');
});

await new Promise((resolveListen, rejectListen) => {
  server.once('error', rejectListen);
  server.listen(0, '127.0.0.1', resolveListen);
});

const address = server.address();
if (!address || typeof address === 'string') {
  throw new Error('failed to determine restrictive-CSP test server address');
}

const launchOptions = {
  headless: true,
  args: [
    `--disable-extensions-except=${extensionDir}`,
    `--load-extension=${extensionDir}`,
  ],
};
if (process.env.CHROMIUM_PATH) {
  launchOptions.executablePath = process.env.CHROMIUM_PATH;
} else {
  launchOptions.channel = 'chromium';
}

let context;
try {
  context = await chromium.launchPersistentContext(userDataDir, launchOptions);
  await context.addInitScript(() => {
    window.__bursaProviderStatuses = [];
    window.addEventListener('message', (event) => {
      if (event.source === window && event.data?.source === 'bursa-cip30-provider-status') {
        window.__bursaProviderStatuses.push(event.data);
      }
    });
  });

  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${address.port}/`, { waitUntil: 'domcontentloaded' });
  await page
    .waitForFunction(
      () =>
        (Boolean(window.cardano?.bursa) &&
          window.__bursaProviderStatuses.some((status) => status.status === 'ready')) ||
        window.__bursaProviderStatuses.some((status) => status.status === 'error'),
      undefined,
      { timeout: 5_000 },
    )
    .catch(() => undefined);

  const result = await page.evaluate(() => ({
    providerAvailable: Boolean(window.cardano?.bursa),
    registrationReady: window.__bursaProviderStatuses.some(
      (status) => status.status === 'ready',
    ),
    failure: window.__bursaProviderStatuses.find((status) => status.status === 'error'),
  }));

  assert.ok(
    result.providerAvailable || result.failure,
    'provider was not registered and no injection failure was reported',
  );
  assert.equal(
    result.failure,
    undefined,
    `provider registration failed: ${result.failure?.error}`,
  );
  assert.equal(result.providerAvailable, true);
  assert.equal(result.registrationReady, true, 'provider registration was not reported ready');
} finally {
  await context?.close();
  await new Promise((resolveClose) => server.close(resolveClose));
  await rm(userDataDir, { recursive: true, force: true });
}
