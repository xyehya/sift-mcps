import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

// Self-hosted fonts (no Google Fonts / gstatic) — spec §5.1.
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/fira-code/400.css'
import '@fontsource/fira-code/500.css'

import './styles/globals.css'

import { ThemeProvider } from '@/lib/theme'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Toaster } from '@/components/ui/sonner'
import App from '@/App'

// ─────────────────────────────────────────────────────────────────────────
// Mount the auth-gated AppShell. A DEV-ONLY `?mock` branch seeds demo fixtures
// and renders the shell behind a mock auth context (no backend needed) so the
// reference tabs can be reviewed/screenshotted populated. The branch is gated
// by `import.meta.env.DEV` and loads fixtures via dynamic import(), so the
// production bundle tree-shakes all mock code out.
// ─────────────────────────────────────────────────────────────────────────

async function resolveTree() {
  const params = new URLSearchParams(window.location.search)
  if (import.meta.env.DEV && params.has('mock')) {
    const [{ installMockData }, { AuthContext }, { AppShell }] = await Promise.all([
      import('@/_mock/install'),
      import('@/lib/auth-context'),
      import('@/components/layout/AppShell'),
    ])
    const user = await installMockData()
    const mockAuth = { status: 'authed', user, login() {}, logout() {} }
    return (
      <AuthContext.Provider value={mockAuth}>
        <AppShell />
        <Toaster />
      </AuthContext.Provider>
    )
  }
  return (
    <>
      <App />
      <Toaster />
    </>
  )
}

resolveTree().then((tree) => {
  createRoot(document.getElementById('root')).render(
    <StrictMode>
      <ThemeProvider>
        <TooltipProvider delayDuration={150}>{tree}</TooltipProvider>
      </ThemeProvider>
    </StrictMode>,
  )
})
