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
import { Showcase } from '@/_showcase/Showcase'

// Phase 0 RUN-1 smoke target: design-system showcase (replaced by AppShell in RUN-2).
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <TooltipProvider delayDuration={150}>
        <Showcase />
        <Toaster />
      </TooltipProvider>
    </ThemeProvider>
  </StrictMode>,
)
