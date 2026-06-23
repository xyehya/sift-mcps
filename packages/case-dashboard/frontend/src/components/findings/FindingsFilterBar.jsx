import { useEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'

import { cn } from '@/lib/utils'

// ─────────────────────────────────────────────────────────────────────────
// FindingsList filter bar — the "N shown" header + Filter dropdown trigger and
// its glass panel of segmented controls (Severity / State / Time). Colors are
// literal token utility classes; the panel's blur/saturate/drop-in animation
// are layout effects expressed as arbitrary token classes (no inline color).
// ─────────────────────────────────────────────────────────────────────────

// ── Segmented control (filter panel groups) ────────────────────────────

function Segmented({ label, options, value, onChange }) {
  return (
    <div>
      <div className="mono mb-2 text-[9px] uppercase tracking-[.12em] text-text-ghost">
        {label}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {options.map((opt) => {
          const active = value === opt.value
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onChange(opt.value)}
              className={cn(
                'mono rounded-[6px] border bg-transparent px-2.5 py-1 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                active ? 'bg-orange/12 border-orange/40 text-orange' : 'border-border-soft text-text-muted',
              )}
            >
              {opt.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ── Filter option sets ─────────────────────────────────────────────────

const SEV_OPTIONS = [
  { value: 'ALL', label: 'All' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
]

const STATE_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'staged', label: 'Staged' },
  { value: 'rejected', label: 'Rejected' },
]

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest' },
  { value: 'oldest', label: 'Oldest' },
]

// ── Filter dropdown panel ──────────────────────────────────────────────

function FilterPanel({ open, onClose, sevFilter, onSevFilter, stateFilter, onStateFilter, sortFilter, onSortFilter, activeCount, onClearAll }) {
  const panelRef = useRef(null)

  // Close on outside click / Escape
  useEffect(() => {
    if (!open) return
    function handleClick(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) onClose()
    }
    function handleKey(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', handleClick)
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('mousedown', handleClick)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open, onClose])

  if (!open) return null

  return (
    // Lightly translucent glass panel with drop-in animation (token easing).
    <div
      ref={panelRef}
      className="absolute left-2 right-2 top-full z-20 mt-1 rounded-[10px] border border-border-soft bg-bg-overlay/82 p-4 shadow-lg backdrop-blur-[16px] backdrop-saturate-[1.4] animate-[dropin_.22s_var(--ease-snap)_both]"
    >
      <div className="flex flex-col gap-4">
        <Segmented label="Confidence" options={SEV_OPTIONS} value={sevFilter} onChange={onSevFilter} />
        <Segmented label="State" options={STATE_OPTIONS} value={stateFilter} onChange={onStateFilter} />
        <Segmented label="Time" options={SORT_OPTIONS} value={sortFilter} onChange={onSortFilter} />
        {activeCount > 0 && (
          <button
            type="button"
            onClick={onClearAll}
            className="mono self-start text-[11px] font-semibold text-text-muted underline"
          >
            Clear all
          </button>
        )}
      </div>
    </div>
  )
}

// ── Filter bar (export) ────────────────────────────────────────────────

export function FilterBar({ shown, sevFilter, onSevFilter, stateFilter, onStateFilter, sortFilter, onSortFilter, activeCount, onClearAll }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="relative border-b border-border-soft px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="mono text-[11px] text-text-muted">
          {shown} shown
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className={cn(
            'mono flex items-center gap-1.5 rounded-[7px] border bg-transparent px-2.5 py-1 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            open || activeCount > 0 ? 'bg-orange/10 border-orange/30 text-orange' : 'border-border-soft text-text-muted',
          )}
        >
          {/* funnel icon */}
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
          </svg>
          Filter
          {activeCount > 0 && (
            <span className="mono flex size-4 items-center justify-center rounded-full bg-orange text-[9px] font-bold text-[var(--on-accent)]">
              {activeCount}
            </span>
          )}
          <ChevronDown
            className="size-3 transition-transform"
            // Data-driven numeric rotation (open state) per §11.
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
            aria-hidden
          />
        </button>
      </div>

      <FilterPanel
        open={open}
        onClose={() => setOpen(false)}
        sevFilter={sevFilter}
        onSevFilter={onSevFilter}
        stateFilter={stateFilter}
        onStateFilter={onStateFilter}
        sortFilter={sortFilter}
        onSortFilter={onSortFilter}
        activeCount={activeCount}
        onClearAll={onClearAll}
      />
    </div>
  )
}
