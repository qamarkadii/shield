import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';
// Two pages are built into dist/:
//   index.html  -> citizen website  (aidashield.tech,     served by backend/app/public.py)
//   admin.html  -> analyst console  (app.aidashield.tech, served by backend/app/main.py)
// Dev: "npm run dev:shield" talks to a running Shield (python run_shield.py) through this proxy.
export default defineConfig({ plugins: [react(), tailwindcss()],
  build: { chunkSizeWarningLimit: 1600,
    rollupOptions: { input: { index: resolve(__dirname, 'index.html'), admin: resolve(__dirname, 'admin.html') } } },
  server: { proxy: { '/api': 'http://127.0.0.1:8001' } } });
