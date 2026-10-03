import { describe, expect, it } from 'vitest';
import source from '../manifest.json';
import { buildManifest } from '../manifest';

describe('buildManifest', () => {
  it('keeps the service worker and drops Firefox-only keys for Chrome', () => {
    const manifest = buildManifest(source, 'chrome');
    expect(manifest.background).toEqual({ service_worker: 'background.js', type: 'module' });
    expect(manifest.browser_specific_settings).toBeUndefined();
    expect(manifest.minimum_chrome_version).toBe('111');
  });

  it('uses background scripts and drops Chrome-only keys for Firefox', () => {
    const manifest = buildManifest(source, 'firefox');
    expect(manifest.background).toEqual({ scripts: ['background.js'], type: 'module' });
    expect(manifest.minimum_chrome_version).toBeUndefined();
    expect(manifest.browser_specific_settings.gecko).toMatchObject({
      id: 'bursa-connector@blinklabs.io',
      strict_min_version: '140.0',
    });
    expect(manifest.browser_specific_settings.gecko.data_collection_permissions.required).not.toContain(
      'none',
    );
    expect(manifest.browser_specific_settings.gecko_android.strict_min_version).toBe('142.0');
  });

  it('registers the provider in MAIN and the relay in the isolated world at document_start', () => {
    for (const target of ['chrome', 'firefox'] as const) {
      const scripts = buildManifest(source, target).content_scripts.map(
        ({ js, run_at, world }: { js: string[]; run_at: string; world: string }) => ({ js, run_at, world }),
      );
      expect(scripts).toEqual([
        { js: ['content.js'], run_at: 'document_start', world: 'ISOLATED' },
        { js: ['injected.js'], run_at: 'document_start', world: 'MAIN' },
      ]);
      expect(buildManifest(source, target).web_accessible_resources).toBeUndefined();
    }
  });

  it('does not mutate the source manifest', () => {
    const before = JSON.stringify(source);
    buildManifest(source, 'firefox');
    buildManifest(source, 'chrome');
    expect(JSON.stringify(source)).toBe(before);
  });
});
