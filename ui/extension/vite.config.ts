import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { zipSync } from 'fflate';
import { defineConfig } from 'vite';
import { buildManifest } from './manifest';

function listFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory() ? listFiles(join(dir, entry.name)) : [join(dir, entry.name)],
    )
    .sort();
}

// `vite build --mode chrome|firefox` writes one loadable tree per browser and a
// package of it beside the tree. The zip is written here, not by web-ext, because
// web-ext stamps entries with the current time and in completion order, which makes
// every package differ; sorted entries and a fixed local-time epoch do not.
export default defineConfig(({ mode }) => {
  const target = mode === 'firefox' ? 'firefox' : 'chrome';
  const source = JSON.parse(readFileSync(resolve(__dirname, 'manifest.json'), 'utf8'));
  let outDir = '';
  return {
    plugins: [
      {
        name: 'bursa-extension',
        configResolved(config) {
          outDir = resolve(config.root, config.build.outDir);
        },
        generateBundle() {
          this.emitFile({
            type: 'asset',
            fileName: 'manifest.json',
            source: `${JSON.stringify(buildManifest(source, target), null, 2)}\n`,
          });
        },
        closeBundle() {
          const mtime = new Date(1980, 0, 1);
          const entries = Object.fromEntries(
            listFiles(outDir).map((file) => [
              relative(outDir, file).split('\\').join('/'),
              [readFileSync(file), { mtime, level: 9 }] as const,
            ]),
          );
          // emptyOutDir clears only this browser's tree, so a package from an earlier
          // version would otherwise sit beside the new one.
          const packages = join(outDir, '..');
          const prefix = `bursa-connector-${target}-`;
          for (const name of readdirSync(packages)) {
            if (name.startsWith(prefix) && name.endsWith('.zip')) rmSync(join(packages, name));
          }
          writeFileSync(join(packages, `${prefix}${source.version}.zip`), zipSync(entries));
        },
      },
    ],
    build: {
      outDir: `dist/${target}`,
      emptyOutDir: true,
      rollupOptions: {
        input: {
          background: resolve(__dirname, 'src/background.ts'),
          content: resolve(__dirname, 'src/content.ts'),
          injected: resolve(__dirname, 'src/injected.ts'),
          popup: resolve(__dirname, 'src/popup.ts'),
        },
        output: {
          entryFileNames: '[name].js',
          chunkFileNames: 'chunks/[name]-[hash].js',
          assetFileNames: '[name].[ext]',
        },
      },
    },
    test: {
      environment: 'jsdom',
      globals: true,
      include: ['tests/**/*.test.ts'],
    },
  };
});
