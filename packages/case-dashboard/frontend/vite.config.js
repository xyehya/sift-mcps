import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/portal/',
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
