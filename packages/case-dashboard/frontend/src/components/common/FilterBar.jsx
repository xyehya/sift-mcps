import { Search } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'

// ─────────────────────────────────────────────────────────────────────────
// FilterBar primitives — the shared search / select / toggle-chip controls for
// the entity tabs. Mission-Control reskin of the legacy inline-styled filter
// rows (search box + <select>s + type chips), now token-class only (no inline
// style, no raw hex). Pure presentation; the owning tab holds filter state.
// ─────────────────────────────────────────────────────────────────────────

/** Search input with a leading icon. */
export function SearchInput({ value, onChange, placeholder = 'Search…', className, label }) {
  return (
    <div className={cn('relative', className)}>
      <Search
        className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label ?? placeholder}
        className="mono h-8 pl-8 text-xs"
      />
    </div>
  )
}

/** Native select styled to the token system (small, mono). */
export function SelectFilter({ value, onChange, options, label, className }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      className={cn(
        'mono h-8 rounded-md border border-input bg-transparent px-2 text-xs text-foreground outline-none transition-[color,box-shadow] focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50',
        className,
      )}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  )
}

/**
 * ToggleChip — a single multi-select filter chip. `activeClass` is a STATIC
 * token class bundle supplied by the caller (JIT-safe), applied when active.
 */
export function ToggleChip({ active, onClick, activeClass, children }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'mono rounded-md border px-2 py-1 text-[10px] uppercase tracking-wider transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active
          ? cn('font-semibold', activeClass)
          : 'border-border-soft text-muted-foreground hover:border-border-hard hover:text-foreground',
      )}
    >
      {children}
    </button>
  )
}

/** Result count pill ("N events" / "N of M"). */
export function ResultCount({ children }) {
  return <span className="mono ml-auto shrink-0 text-[10px] text-muted-foreground">{children}</span>
}
