import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const backend = 'http://127.0.0.1:58951';

export default defineConfig({
  plugins: [svelte()],
  build: {
    sourcemap: false,
  },
  server: {
    // Dev server on localhost only. The API is proxied to the backend so the
    // app stays same-origin (cookies, CSRF checks) exactly like production.
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: backend,
        configure: (proxy) => {
          proxy.on('proxyReq', (request) => request.setHeader('origin', 'http://localhost:58951'));
        },
      },
    },
  },
});
