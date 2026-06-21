import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Cpu, Database, FileText, HardDrive, Search, ShieldCheck, Wifi,
} from 'lucide-react'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { custodyClass, typeMeta, formatAcquired, shortHash } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceList — registry master pane (left column of the master-detail split).
// Each row: EV-id · artifact name · type badge · host · size · acquired timestamp
// · hash-seal chip · custody status badge. Click selects the row; the detail
// panel renders the full artifact in the right column.
// ─────────────────────────────────────────────────────────────────────────

const TYPE_ICON = {
  hdd: HardDrive,
  cpu: Cpu,
  wifi: Wifi,
  scroll: FileText,
  database: Database,
  file: FileText,
}

function TypeIcon({ type, className }) {
  const { icon } = typeMeta(type)
  const Icon = TYPE_ICON[icon] ?? FileText
  return <Icon className={cn('size-3.5 shrink-0', className)} aria-hidden />
}

/** Jade shield seal-chip reusing the Findings hash-chip pattern. */
function SealChip({ id, sha256, custodyStatus }) {
  const isSealed = (custodyStatus ?? '').toLowerCase() === 'sealed'
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'mono inline-flex items-center gap-1 rounded-md border px-1.5 py-px text-[10px] font-semibold cursor-default',
            isSealed
              ? 'border-status-approved/40 bg-status-approved/10 text-status-approved'
              : 'border-border bg-secondary text-muted-foreground',
          )}
        >
          <ShieldCheck className="size-2.5 shrink-0" aria-hidden />
          {id}
        </span>
      </TooltipTrigger>
      <TooltipContent className="mono max-w-xs break-all text-[10px]">
        {sha256 || 'Hash not yet recorded'}
      </TooltipContent>
    </Tooltip>
  )
}

/** Single evidence row in the list. */
function EvidenceRow({ item, isSelected, onSelect, variants }) {
  const custody = custodyClass(item.custody_status)
  const { label: typeLabel } = typeMeta(item.type)

  return (
    <motion.button
      type="button"
      variants={variants.staggerItem}
      onClick={() => onSelect(item.id)}
      aria-selected={isSelected}
      aria-label={`${item.id}: ${item.name}, ${item.custody_status}`}
      className={cn(
        'w-full cursor-pointer rounded-lg border px-3 py-2.5 text-left transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        isSelected
          ? 'border-primary/40 bg-primary/8'
          : 'border-transparent hover:border-border hover:bg-secondary',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        {/* Left: id + name */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <TypeIcon type={item.type} className="text-muted-foreground" />
            <span
              className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
            >
              {item.id}
            </span>
            <Badge
              variant="secondary"
              className="mono h-4 px-1.5 py-0 text-[9px] font-semibold uppercase tracking-wider"
            >
              {typeLabel}
            </Badge>
          </div>
          <p
            className="mono mt-0.5 truncate text-xs font-semibold"
            style={{ color: 'var(--text-bright)' }}
          >
            {item.name}
          </p>
          <p className="mono mt-0.5 truncate text-[10px] text-muted-foreground">
            {item.host} · {item.size_label ?? '—'}
          </p>
        </div>

        {/* Right: custody badge */}
        <Badge
          variant="outline"
          className={cn('mono mt-0.5 shrink-0 text-[9px]', custody.text, custody.ring)}
        >
          <span className={cn('mr-1 inline-block size-1.5 rounded-full', custody.dot)} aria-hidden />
          {custody.label}
        </Badge>
      </div>

      {/* Bottom: hash chip + acquired */}
      <div className="mt-2 flex items-center justify-between gap-2">
        <SealChip id={item.id} sha256={item.sha256} custodyStatus={item.custody_status} />
        <span className="mono text-[10px] text-muted-foreground">
          {formatAcquired(item.acquired_at)}
        </span>
      </div>
    </motion.button>
  )
}

/** Empty-state for the list. */
function EmptyState({ hasSearch }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-muted-foreground">
      <ShieldCheck className="size-10 opacity-30" aria-hidden />
      <p className="text-sm font-semibold">
        {hasSearch ? 'No artifacts match your search' : 'No evidence items registered'}
      </p>
      {!hasSearch && (
        <p className="max-w-xs text-xs opacity-70">
          Acquired artifacts appear here once registered and sealed to the chain of custody.
        </p>
      )}
    </div>
  )
}

export function EvidenceList({ items, selectedId, onSelect, loading }) {
  const variants = useMotionVariants()
  const [search, setSearch] = useState('')

  const filtered = search
    ? items.filter((i) =>
        i.id.toLowerCase().includes(search.toLowerCase()) ||
        i.name.toLowerCase().includes(search.toLowerCase()) ||
        (i.host ?? '').toLowerCase().includes(search.toLowerCase()) ||
        (i.type ?? '').toLowerCase().includes(search.toLowerCase()),
      )
    : items

  return (
    <div className="flex h-full flex-col overflow-hidden border-r border-border">
      {/* Search bar */}
      <div className="shrink-0 border-b border-border px-3 py-2.5">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search artifacts…"
            aria-label="Search evidence items"
            className="mono h-8 pl-8 text-xs"
          />
        </div>
        <p className="mono mt-1.5 text-[10px] text-muted-foreground">
          {filtered.length} of {items.length} artifact{items.length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* List */}
      <ScrollArea className="flex-1">
        <div className="p-2">
          {loading ? (
            <div className="space-y-2 p-1">
              {Array.from({ length: 6 }, (_, i) => (
                <Skeleton key={i} className="h-[68px] w-full rounded-lg" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState hasSearch={Boolean(search)} />
          ) : (
            <motion.div
              variants={variants.staggerContainer}
              initial="hidden"
              animate="show"
              className="space-y-1"
            >
              {filtered.map((item) => (
                <EvidenceRow
                  key={item.id}
                  item={item}
                  isSelected={item.id === selectedId}
                  onSelect={onSelect}
                  variants={variants}
                />
              ))}
            </motion.div>
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
