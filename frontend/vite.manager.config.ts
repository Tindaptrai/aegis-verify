import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Set AEGIS_MANAGER_PROXY_TARGET to the Django origin for Manager development.
// A missing target fails explicitly instead of proxying to the dashboard server.
export default defineConfig(({ command, mode }) => {
  const target = loadEnv(mode, '.', 'AEGIS_').AEGIS_MANAGER_PROXY_TARGET;
  if (command === 'serve' && !target) throw new Error('Set AEGIS_MANAGER_PROXY_TARGET to the Django origin');
  return {
    plugins: [react()], base: '/static/manager/',
    server: { host: 'localhost', port: 5174, strictPort: true, proxy: target ? { '/api/v1': { target, changeOrigin: false }, '/api/v2': { target, changeOrigin: false } } : undefined },
    build: { outDir: 'dist-manager', emptyOutDir: true, sourcemap: false, rollupOptions: { input: 'manager.html' } },
  };
});
