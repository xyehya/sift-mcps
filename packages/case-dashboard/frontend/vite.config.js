import fs from 'node:fs'
import https from 'node:https'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// ── Dev API proxy (F6) ──────────────────────────────────────────────────────
// The gateway is HTTPS with a private CA. For a verified TLS path we load the
// VM CA into an https.Agent instead of disabling verification (`secure:false`).
// Both the target and the CA path are env-overridable so no host/IP is baked in.
//
// GUARD: the default dev flow runs against mock data (`?mock=1`, no proxy), so
// startup must NEVER crash when the CA file is absent. We only attach the
// verified agent if the CA file exists; otherwise we log one warning and fall
// back to `secure:false` (dev-only). Production/live must provide the CA via
// VITE_PROXY_CA so TLS is actually verified.
const PROXY_TARGET = process.env.VITE_API_PROXY ?? 'https://192.168.122.81:4508'
const PROXY_CA = process.env.VITE_PROXY_CA ?? '/home/yk/.sift-vm-ca-192.168.122.81.pem'

function buildProxyConfig() {
  const base = { target: PROXY_TARGET, changeOrigin: true }
  if (fs.existsSync(PROXY_CA)) {
    // Verified TLS: trust only the supplied CA.
    return { ...base, agent: new https.Agent({ ca: fs.readFileSync(PROXY_CA) }) }
  }
  // Fallback (dev-only): CA absent → don't crash dev startup. TLS is NOT
  // verified here; prod/live must set VITE_PROXY_CA to the VM CA.
  console.warn(
    `[vite] proxy CA not found at ${PROXY_CA} — falling back to secure:false ` +
      `(dev-only, TLS unverified). Set VITE_PROXY_CA for a verified path.`,
  )
  return { ...base, secure: false }
}

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
      '/portal/api': buildProxyConfig(),
    },
  },
})
