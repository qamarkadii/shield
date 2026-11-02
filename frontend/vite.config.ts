import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
// Dev: "npm run dev:shield" talks to a running Shield (python run_shield.py) through this proxy.
export default defineConfig({ plugins: [react(), tailwindcss()], build: { chunkSizeWarningLimit: 1600 },
  server: { proxy: { '/api': 'http://127.0.0.1:8001' } } });
