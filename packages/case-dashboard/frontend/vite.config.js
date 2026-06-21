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
    rollupOptions: {
      output: {
        // Split heavy vendors into their own chunks (PERF-1) so the main entry
        // chunk drops well under Rollup's 500 kB warning. Each group is a
        // distinct, cacheable bundle; recharts/framer-motion are large and only
        // needed by a subset of tabs, which lazy-loading + these splits isolate.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('recharts') || id.includes('d3-')) return 'vendor-charts'
          if (id.includes('framer-motion') || id.includes('motion-dom') || id.includes('motion-utils')) {
            return 'vendor-motion'
          }
          if (id.includes('@radix-ui') || id.includes('radix-ui')) return 'vendor-radix'
          if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) {
            return 'vendor-react'
          }
          return 'vendor'
        },
      },
    },
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
