import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';

const systemChrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 45_000,
  expect: { timeout: 12_000 },
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:43179',
    viewport: { width: 1440, height: 1000 },
    launchOptions: { executablePath: process.env.STAKE_BROWSER ?? (existsSync(systemChrome) ? systemChrome : undefined) },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node --import tsx tests/e2e/serve.ts',
    url: 'http://127.0.0.1:43179/api/workspace',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
