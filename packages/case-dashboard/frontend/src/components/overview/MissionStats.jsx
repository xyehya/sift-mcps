import { motion } from 'framer-motion'
import { Archive, Crosshair, Flame, Server } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab, navigateToFindings } from '@/hooks/useHashRoute'
import { useMotionVariants, useCountUp } from '@/lib/motion'
import { missionTiles } from '@/lib/agent-state'
import { Card } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// MissionStats — the 2×2 KPI tiles (Evidence sealed/total · High severity ·
// IOCs · MCP backends up/total + degraded). UNIFORM grid: equal-height tiles
// (auto-rows-fr + h-full), equal visual weight, no oversized tile (RUN-4c #31).
// Numerals count up on load; the degraded-backend tile pulses. EVERY tile
// deep-links: Evidence→Evidence, High→Findings filtered to HIGH confidence
// (hash `?sev=high` + status reset), IOCs→IOCs, MCP backends→Backends. Values
// derive from portalState (DB authority) + chain/findings/ioc slices via
// missionTiles() — no new store keys. Reduced-motion safe throughout.
// ─────────────────────────────────────────────────────────────────────────

const ICONS = { archive: Archive, flame: Flame, crosshair: Crosshair, server: Server }
const TILE_TAB = { evidence: 'evidence', iocs: 'iocs', backends: 'backends' }
const TILE_GOTO = {
  evidence: 'Evidence',
  high: 'Findings (High confidence)',
  iocs: 'IOCs',
  backends: 'Backends',
}

function TileValue({ value, tone }) {
  const numeric = typeof value === 'number'
  const counted = useCountUp(numeric ? value : 0)
  // Numeric KPIs stay uniform (foreground); a non-numeric status word (e.g. the
  // Evidence OK/Warning tile) takes the tile tone so the status reads at a glance.
  return (
    <span className={cn('tnum font-display text-[26px] font-bold leading-none', numeric ? 'text-foreground' : (tone ?? 'text-foreground'))}>
      {numeric ? Math.round(counted).toLocaleString() : value}
    </span>
  )
}

function Tile({ tile, onOpen, variants }) {
  const Icon = ICONS[tile.icon] ?? Archive
  const degraded = tile.key === 'backends' && /degraded/.test(tile.foot)
  return (
    <motion.div variants={variants.staggerItem} className="h-full">
      <Tooltip>
        <TooltipTrigger asChild>
          <Card
            role="button"
            tabIndex={0}
            aria-label={`${tile.label}: ${tile.value}${tile.sub ? ` ${tile.sub}` : ''} — ${tile.foot}. Open ${TILE_GOTO[tile.key] ?? 'view'}.`}
            onClick={onOpen}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onOpen()
              }
            }}
            className="h-full cursor-pointer justify-between gap-2 p-4 transition-shadow hover:ring-2 hover:ring-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{tile.label}</span>
              {degraded ? (
                <motion.span variants={variants.statusDotPulse} animate="animate" aria-hidden>
                  <Icon className={cn('size-4', tile.tone)} />
                </motion.span>
              ) : (
                <Icon className={cn('size-4', tile.tone)} aria-hidden />
              )}
            </div>
            <div className="flex items-baseline gap-1">
              <TileValue value={tile.value} tone={tile.tone} />
              {tile.sub && <span className="mono text-xs text-muted-foreground">{tile.sub}</span>}
            </div>
            <div className={cn('text-[11px]', tile.tone)}>{tile.foot}</div>
          </Card>
        </TooltipTrigger>
        <TooltipContent>{tile.label}: {tile.foot} · open {TILE_GOTO[tile.key] ?? 'view'}</TooltipContent>
      </Tooltip>
    </motion.div>
  )
}

export function MissionStats() {
  const variants = useMotionVariants()
  const { portalState, chainStatus, findings, iocs, setActiveTab, setFindingsFilter } = useStoreSlice((s) => ({
    portalState: s.portalState,
    chainStatus: s.chainStatus,
    findings: s.findings,
    iocs: s.iocs,
    setActiveTab: s.setActiveTab,
    setFindingsFilter: s.setFindingsFilter,
  }))

  const tiles = missionTiles(portalState, { chainStatus, findings, iocs })

  function open(tile) {
    if (tile.key === 'high') {
      setFindingsFilter('all') // show all HIGH findings regardless of review status
      navigateToFindings(setActiveTab, { sev: 'HIGH' })
    } else {
      navigateToTab(setActiveTab, TILE_TAB[tile.key] ?? 'overview')
    }
  }

  return (
    <motion.div
      variants={variants.staggerContainer}
      initial="hidden"
      animate="show"
      className="grid auto-rows-fr grid-cols-2 gap-4"
    >
      {tiles.map((t) => (
        <Tile key={t.key} tile={t} variants={variants} onOpen={() => open(t)} />
      ))}
    </motion.div>
  )
}
