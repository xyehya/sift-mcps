import { ChevronDown, ChevronUp } from 'lucide-react'

import { cn } from '@/lib/utils'

// ─────────────────────────────────────────────────────────────────────────
// EntityTable — the ONE shared sortable data-table for the entity tabs (Hosts ·
// Accounts · IOCs). Mission-Control reskin of the four divergent legacy tables:
// graphite card, mono uppercase headers, hover row lift, keyboard-reachable
// sort headers with aria-sort. Columns describe label / align / sortable; the
// caller renders each cell via `renderCell`. No business logic here — sorting is
// owned by the caller (entity-utils.sortBy) so it stays unit-testable.
//
// a11y: sortable <th> are real <button>s (keyboard + SR), aria-sort reflects the
// active column; non-sortable headers are plain text (ui-ux `sortable-table`).
// ─────────────────────────────────────────────────────────────────────────

function SortHeader({ col, sortKey, sortAsc, onSort }) {
  const active = sortKey === col.key
  if (!col.sortable) {
    return (
      <th
        className={cn(
          'mono whitespace-nowrap px-3 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground',
          col.align === 'right' && 'text-right',
        )}
      >
        {col.label}
      </th>
    )
  }
  return (
    <th
      aria-sort={active ? (sortAsc ? 'ascending' : 'descending') : 'none'}
      className={cn('px-0 py-0', col.align === 'right' && 'text-right')}
    >
      <button
        type="button"
        onClick={() => onSort(col.key)}
        className={cn(
          'mono inline-flex w-full items-center gap-1 px-3 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
          col.align === 'right' && 'justify-end',
        )}
      >
        {col.label}
        {active ? (
          sortAsc ? (
            <ChevronUp className="size-3" aria-hidden />
          ) : (
            <ChevronDown className="size-3" aria-hidden />
          )
        ) : (
          <ChevronDown className="size-3 opacity-25" aria-hidden />
        )}
      </button>
    </th>
  )
}

export function EntityTable({
  columns,
  rows,
  rowKey,
  renderCell,
  sortKey,
  sortAsc,
  onSort,
  onRowClick,
  caption,
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border-soft bg-card">
      <table className="w-full border-collapse text-left text-xs">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-border-soft bg-secondary/40">
            {columns.map((col) => (
              <SortHeader
                key={col.key}
                col={col}
                sortKey={sortKey}
                sortAsc={sortAsc}
                onSort={onSort}
              />
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border-faint">
          {rows.map((row) => {
            const clickable = !!onRowClick
            return (
              <tr
                key={rowKey(row)}
                onClick={clickable ? () => onRowClick(row) : undefined}
                tabIndex={clickable ? 0 : undefined}
                role={clickable ? 'button' : undefined}
                onKeyDown={
                  clickable
                    ? (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          onRowClick(row)
                        }
                      }
                    : undefined
                }
                className={cn(
                  'text-foreground transition-colors',
                  clickable &&
                    'cursor-pointer hover:bg-secondary/50 focus-visible:bg-secondary/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring',
                )}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={cn(
                      'px-3 py-3 align-top',
                      col.align === 'right' && 'text-right',
                      col.nowrap && 'whitespace-nowrap',
                    )}
                  >
                    {renderCell(row, col.key)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
