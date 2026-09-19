/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server proxies /api to the read-only `aegis dashboard` server so the
// browser only ever talks to one origin. Production builds are served by that
// same Python server from `frontend/dist` (`--static`).
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: { '/api': { target: 'http://127.0.0.1:8765', changeOrigin: false } },
  },
  build: { outDir: 'dist', sourcemap: false, emptyOutDir: true },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.tsx', 'src/**/*.test.ts'],
  },
});
