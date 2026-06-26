import { cn } from '@/lib/utils'

// ─────────────────────────────────────────────────────────────────────────
// MasterDetailLayout (AGENTS §6.5 / §8) — the shared two-pane primitive for any
// list+detail screen. It is the structural cure for the scroll bugs that arise
// when a tab hand-rolls master-detail with magic heights (e.g. the old
// `calc(100vh - 86px)` in FindingsTab):
//
//   • The layout itself is `h-full min-h-0` so it fits the viewport-bounded
//     <main> cell exactly and never grows the shell.
//   • Each pane is a `min-h-0` flex/grid child, so its child can shrink and
//     become a real scroll owner — no magic numbers, zoom-safe.
//   • By default each pane is its OWN scroll owner (`overflow-y-auto`, §8). A
//     pane whose child already manages its internal scroll (its root is
//     `overflow-hidden`, like FindingsList/FindingDetail) passes
//     `scroll={false}` so the layout supplies only the bounded box and the
//     child owns the single scrollbar — avoiding a double scroll owner.
//   • Responsive: below 1024px the two panes STACK vertically (list over
//     detail) per the spec; at ≥1024px they sit side-by-side at `ratio`.
//
// Reuse this for Findings and any future list+detail tab so the anti-scroll-bug
// guarantee in the contract is actually backed by code.
// ─────────────────────────────────────────────────────────────────────────

/**
 * A single bounded pane. `scroll` (default true) makes the pane its own scroll
 * owner; pass `scroll={false}` when the child manages its own internal scroll.
 */
function Pane({ children, scroll = true, className }) {
  return (
    <div
      className={cn(
        'min-h-0 min-w-0',
        scroll ? 'overflow-y-auto overscroll-contain' : 'overflow-hidden',
        className,
      )}
    >
      {children}
    </div>
  )
}

/**
 * Two-pane master-detail layout.
 *
 * @param {React.ReactNode} list   - left/top pane content (the master list).
 * @param {React.ReactNode} detail - right/bottom pane content (the detail view).
 * @param {string} [ratio]         - desktop grid template columns for the two
 *                                    panes. Default `minmax(0,5fr) minmax(0,7fr)`
 *                                    (list:detail = 5:7, the Findings ratio).
 * @param {boolean} [listScroll]   - whether the list pane owns its own scroll
 *                                    (default true). False when the list child
 *                                    manages its internal scroll.
 * @param {boolean} [detailScroll] - same, for the detail pane (default true).
 * @param {boolean} [divider]      - draw a divider between the panes at ≥1024px
 *                                    (right border on the list pane). Default
 *                                    false — opt in when the list child does not
 *                                    already render its own edge.
 * @param {string} [className]     - extra classes on the root.
 * @param {string} [ariaLabel]     - aria-label for the layout region.
 */
export function MasterDetailLayout({
  list,
  detail,
  ratio = 'minmax(0,5fr) minmax(0,7fr)',
  listScroll = true,
  detailScroll = true,
  divider = false,
  className,
  ariaLabel,
}) {
  return (
    <div
      aria-label={ariaLabel}
      className={cn(
        // Mobile/stacked: a min-h-0 flex column (list over detail).
        'flex h-full min-h-0 min-w-0 flex-col',
        // ≥1024px: side-by-side two-column grid at `ratio`.
        'lg:grid',
        className,
      )}
      style={{ gridTemplateColumns: ratio }}
    >
      <Pane
        scroll={listScroll}
        className={cn(divider && 'lg:border-r lg:border-border-faint')}
      >
        {list}
      </Pane>
      <Pane scroll={detailScroll}>{detail}</Pane>
    </div>
  )
}
