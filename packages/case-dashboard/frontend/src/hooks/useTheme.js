// Architecture alias (spec §3 lists hooks/useTheme). The implementation lives
// in lib/theme-context.js alongside the ThemeProvider; re-exported here so
// callers can import the hook from the hooks/ barrel consistently.
export { useTheme } from '@/lib/theme-context'
