import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';

export default defineConfig({
  plugins: [{
    name: 'bundled-runtime-notices',
    generateBundle() {
      const notices = [
        ['@dtelecom/vodozemac-wasm', 'node_modules/@dtelecom/vodozemac-wasm/LICENSE'],
        ['qrcode', 'node_modules/qrcode/license'],
        ['dijkstrajs', 'node_modules/dijkstrajs/LICENSE.md'],
      ].map(([name, path]) => `${name}\n${readFileSync(path, 'utf8')}`).join('\n\n');
      this.emitFile({ type: 'asset', fileName: 'THIRD_PARTY.txt', source: notices });
    },
  }],
  server: {
    host: '127.0.0.1',
    proxy: { '/v1': 'http://127.0.0.1:8765' },
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    outDir: '../server/web_static',
    emptyOutDir: true,
  },
});
