import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
export default defineConfig({
  outputDir: './test-results-browser',
  testDir: './tests/browser-e2e', timeout: 60_000, expect: { timeout: 15_000 }, workers: 1,
  reporter: 'list', use: { baseURL: 'http://127.0.0.1:43181', viewport: { width: 1440, height: 1000 },
    launchOptions: { executablePath: process.env.STAKE_BROWSER ?? (existsSync(chrome) ? chrome : undefined) },
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: { command: 'npm exec -- vite preview --mode browser --host 127.0.0.1 --port 43181 --strictPort', url: 'http://127.0.0.1:43181', reuseExistingServer: false },
});
