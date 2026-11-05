import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig(({ mode, command }) => ({
  define: { 'import.meta.env.VITE_STAKE_RUNTIME': JSON.stringify(mode === 'browser' ? 'browser' : 'server') },
  plugins: [react(), tailwindcss(), ...(mode === 'browser' && command === 'build' ? [{
    name: 'browser-local-content-policy',
    transformIndexHtml() { return [
      { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src 'self' blob:; base-uri 'none'; object-src 'none'; form-action 'none'" }, injectTo: 'head-prepend' as const },
      { tag: 'meta', attrs: { name: 'referrer', content: 'no-referrer' }, injectTo: 'head-prepend' as const },
    ]; },
  }] : [])],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  build: { sourcemap: false, outDir: mode === 'browser' ? 'dist-browser' : 'dist' },
  worker: { format: 'es' },
  server: { host: '127.0.0.1' },
}));
