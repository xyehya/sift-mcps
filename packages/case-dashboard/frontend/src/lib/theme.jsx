import { useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react"
import { Moon, Sun } from "lucide-react"

import { Button } from "@/components/ui/button"
import { ThemeContext, useTheme } from "@/lib/theme-context"

const STORAGE_KEY = "sift-theme"

/** Read the persisted theme setting ('system' | 'light' | 'dark'). */
function readStoredTheme() {
  if (typeof window === "undefined") return "system"
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored === "light" || stored === "dark" || stored === "system") return stored
  } catch {
    /* localStorage unavailable (private mode / disabled) */
  }
  return "system"
}

/** Current OS preference (defaults to dark — Graphite Emerald — when unknown). */
function systemPrefersDark() {
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
  }
  return true
}

/** Apply the resolved theme to <html>: toggle `.dark`, set data-theme + color-scheme. */
function applyTheme(resolved) {
  if (typeof document === "undefined") return
  const root = document.documentElement
  root.classList.toggle("dark", resolved === "dark")
  root.dataset.theme = resolved
  root.style.colorScheme = resolved
}

export function ThemeProvider({ children, defaultTheme = "system" }) {
  const [theme, setThemeState] = useState(() => readStoredTheme() || defaultTheme)
  const [systemDark, setSystemDark] = useState(() => systemPrefersDark())

  // Derived during render — no setState-in-effect.
  const resolvedTheme = useMemo(
    () => (theme === "light" || theme === "dark" ? theme : systemDark ? "dark" : "light"),
    [theme, systemDark],
  )

  // Sync the external system (DOM) before paint. No setState here.
  useLayoutEffect(() => {
    applyTheme(resolvedTheme)
  }, [resolvedTheme])

  // Subscribe to OS preference changes; setState only inside the callback.
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return undefined
    const mql = window.matchMedia("(prefers-color-scheme: dark)")
    const onChange = (event) => setSystemDark(event.matches)
    mql.addEventListener("change", onChange)
    return () => mql.removeEventListener("change", onChange)
  }, [])

  const setTheme = useCallback((next) => {
    setThemeState(next)
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {
      /* persistence best-effort */
    }
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(resolvedTheme === "dark" ? "light" : "dark")
  }, [resolvedTheme, setTheme])

  const value = useMemo(
    () => ({ theme, resolvedTheme, setTheme, toggleTheme }),
    [theme, resolvedTheme, setTheme, toggleTheme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

/** Accessible light/dark toggle. Icon-only → carries an aria-label. */
export function ThemeToggle({ className }) {
  const { resolvedTheme, toggleTheme } = useTheme()
  const isDark = resolvedTheme === "dark"
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={className}
      onClick={toggleTheme}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
    >
      {isDark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
    </Button>
  )
}
