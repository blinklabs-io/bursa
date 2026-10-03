import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Builder } from 'selenium-webdriver';
import firefox from 'selenium-webdriver/firefox.js';
const { Context } = firefox;
import { chromium } from 'playwright';

// Runs an async function body in the page and reports either its value or the
// thrown CIP-30 error, so both drivers return the same shape.
const wrap = (body) => `(async () => {
  try { return { ok: await (async () => { ${body} })() }; }
  catch (e) { return { err: e && e.code !== undefined ? { code: e.code, info: e.info } : String(e) }; }
})()`;

export const FIREFOX_UUID = '5c0cbe2a-0e5f-4b0a-9a3c-1f2f6c0c1d11';
export const FIREFOX_ID = 'bursa-connector@blinklabs.io';

// Every launcher resolves to { origin, open(url), suspendBackground(), close() }, where
// origin is the extension's own origin and open() returns { run(body), close() }.
export async function launchChrome(extensionDir) {
  const userDataDir = await mkdtemp(join(tmpdir(), 'bursa-extension-e2e-'));
  const options = {
    headless: true,
    args: [`--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`],
  };
  if (process.env.CHROMIUM_PATH) options.executablePath = process.env.CHROMIUM_PATH;
  else options.channel = 'chromium';
  const context = await chromium.launchPersistentContext(userDataDir, options);
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  const { protocol, host } = new URL(worker.url());
  const origin = `${protocol}//${host}`;

  return {
    origin,
    async open(url) {
      const page = await context.newPage();
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      return { run: (body) => page.evaluate(wrap(body)), close: () => page.close() };
    },
    async suspendBackground() {
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('ServiceWorker.enable');
      const stopped = new Promise((resolve) =>
        cdp.on('ServiceWorker.workerVersionUpdated', ({ versions }) => {
          if (versions.some((v) => v.runningStatus === 'stopped' && v.scriptURL.startsWith(origin))) {
            resolve();
          }
        }),
      );
      await cdp.send('ServiceWorker.stopAllWorkers');
      await stopped;
      await page.close();
    },
    async close() {
      await context.close();
      await rm(userDataDir, { recursive: true, force: true });
    },
  };
}

export async function launchFirefox(packagePath) {
  const options = new firefox.Options().addArguments('-headless');
  if (process.env.FIREFOX_PATH) options.setBinary(process.env.FIREFOX_PATH);
  // Pin the extension's internal UUID so the popup URL is known, and let the
  // event page go idle quickly so suspension is exercised.
  options.setPreference('extensions.webextensions.uuids', JSON.stringify({ [FIREFOX_ID]: FIREFOX_UUID }));
  options.setPreference('extensions.background.idle.timeout', 1000);
  process.env.MOZ_REMOTE_ALLOW_SYSTEM_ACCESS = '1';
  const driver = await new Builder().forBrowser('firefox').setFirefoxOptions(options).build();
  await driver.installAddon(packagePath, true);

  return {
    origin: `moz-extension://${FIREFOX_UUID}`,
    async open(url) {
      const known = await driver.getAllWindowHandles();
      if (url.startsWith('moz-extension:')) {
        // Marionette refuses to navigate content to extension pages, so the
        // browser itself opens the tab, as it does for a toolbar popup.
        await driver.setContext(Context.CHROME);
        await driver.executeScript(
          `gBrowser.selectedTab = gBrowser.addTab(arguments[0], {
            triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
          });`,
          url,
        );
        await driver.setContext(Context.CONTENT);
      } else {
        await driver.switchTo().newWindow('tab');
        await driver.get(url);
      }
      const handle = (await driver.getAllWindowHandles()).find((h) => !known.includes(h));
      return {
        run: async (body) => {
          await driver.switchTo().window(handle);
          return driver.executeAsyncScript(
            `const done = arguments[arguments.length - 1]; ${wrap(body)}.then(done);`,
          );
        },
        close: async () => {
          await driver.switchTo().window(handle);
          await driver.close();
          const [first] = await driver.getAllWindowHandles();
          await driver.switchTo().window(first);
        },
      };
    },
    async suspendBackground() {
      await driver.setContext(Context.CHROME);
      await driver.wait(
        () =>
          driver.executeScript(
            `return WebExtensionPolicy.getByID(arguments[0]).extension.backgroundState === 'stopped';`,
            FIREFOX_ID,
          ),
        15_000,
        'the event page did not go idle',
      );
      await driver.setContext(Context.CONTENT);
    },
    close: () => driver.quit(),
  };
}
