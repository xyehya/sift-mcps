import { createContext, useContext } from "react"

// Separated from theme.jsx so that theme.jsx only exports components
// (keeps react-refresh fast-refresh happy). Holds the context + hook only.
export const ThemeContext = createContext(null)

/** Access the active theme. Must be used within <ThemeProvider>. */
export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error("useTheme must be used within a ThemeProvider")
  return ctx
}
