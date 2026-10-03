import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { unzipSync } from 'fflate';
import { build } from 'vite';
import { afterAll, describe, expect, it } from 'vitest';
import source from '../manifest.json';
import { buildManifest } from '../manifest';

const root = resolve(__dirname, '..');
const scratch = mkdtempSync(join(tmpdir(), 'bursa-extension-'));

afterAll(() => rmSync(scratch, { recursive: true, force: true }));

async function buildPackage(target: 'chrome' | 'firefox', name: string): Promise<Buffer> {
  await build({
    root,
    mode: target,
    logLevel: 'silent',
    build: { outDir: join(scratch, name, target) },
  });
  return readFileSync(join(scratch, name, `bursa-connector-${target}-${source.version}.zip`));
}

describe('extension package', () => {
  it.each(['chrome', 'firefox'] as const)('%s package has the manifest at the archive root', async (target) => {
    const files = unzipSync(await buildPackage(target, 'root'));
    expect(Object.keys(files)).toEqual(
      expect.arrayContaining(['manifest.json', 'background.js', 'content.js', 'injected.js', 'popup.js', 'popup.html']),
    );
    expect(JSON.parse(Buffer.from(files['manifest.json']).toString())).toEqual(
      buildManifest(source, target),
    );
  });

  it.each(['chrome', 'firefox'] as const)('%s package is byte-identical across builds', async (target) => {
    const first = await buildPackage(target, 'first');
    await new Promise((done) => setTimeout(done, 2_100));
    expect(await buildPackage(target, 'second')).toEqual(first);
  });
});
