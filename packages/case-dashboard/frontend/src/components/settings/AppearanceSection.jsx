import { Monitor, Moon, Sun } from 'lucide-react'

import { useTheme } from '@/lib/theme-context'

// ─────────────────────────────────────────────────────────────────────────
// AppearanceSection — theme preference control. Uses the EXISTING lib/theme
// provider (useTheme → setTheme), never a new mechanism (brief requirement):
// system / light / dark, persisted by ThemeProvider to localStorage and applied
// to <html> via the .dark class. The active option carries the orange accent.
// ─────────────────────────────────────────────────────────────────────────

const OPTIONS = [
  { value: 'system', label: 'System', Icon: Monitor },
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
]

export function AppearanceSection() {
  const { theme, setTheme } = useTheme()
  return (
    <div className="rounded-lg border border-border-faint bg-card p-4">
      <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
        Appearance
      </p>
      <div role="radiogroup" aria-label="Theme preference" className="flex flex-wrap gap-2">
        {OPTIONS.map(({ value, label, Icon }) => {
          const active = theme === value
          return (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => setTheme(value)}
              className={`mono flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                active
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border-soft bg-bg-raised text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon className="size-3.5" aria-hidden />
              {label}
            </button>
          )
        })}
      </div>
    </div>
  )
}
