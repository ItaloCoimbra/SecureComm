import { defineConfig } from '@playwright/test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const temporary = mkdtempSync(join(tmpdir(), 'securecomm-web-e2e-'));
const python = process.env.SECURECOMM_TEST_PYTHON
  ?? (process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python');

export default defineConfig({
  testDir: './e2e',
  timeout: 90000,
  expect: { timeout: 15000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8766',
    headless: true,
    // Synthetic data only. Never enable tracing of real private conversations.
    trace: 'off',
    screenshot: 'only-on-failure',
    permissions: ['microphone'],
    launchOptions: {
      args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
    },
  },
  webServer: {
    command: `"${python}" -m server.web_server --host 127.0.0.1 --port 8766 --database "${join(temporary, 'relay.sqlite')}"`,
    cwd: '..',
    url: 'http://127.0.0.1:8766/v1/health',
    reuseExistingServer: false,
    timeout: 30000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
