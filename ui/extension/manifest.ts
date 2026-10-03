export type Target = 'chrome' | 'firefox';

// The manifest source declares both background forms and both browsers' settings;
// each browser rejects or warns about the other's keys, so every target drops them.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildManifest(source: any, target: Target): any {
  const manifest = structuredClone(source);
  if (target === 'chrome') {
    delete manifest.browser_specific_settings;
    delete manifest.background.scripts;
  } else {
    delete manifest.minimum_chrome_version;
    delete manifest.background.service_worker;
  }
  return manifest;
}
