import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/portal/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../src/case_dashboard/static/v2',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/portal/api': {
        target: 'https://192.168.122.81:4508',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
