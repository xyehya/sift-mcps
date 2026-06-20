import { motion } from 'framer-motion'
import { Archive, Crosshair, Flame, Server } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { useMotionVariants, useCountUp } from '@/lib/motion'
import { missionTiles } from '@/lib/agent-state'
import { Card } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// MissionStats — the 2×2 KPI tiles (Evidence sealed/total · High severity ·
// IOCs · MCP backends up/total + degraded). Numerals count up on load; the
// degraded-backend tile pulses (statusDotPulse). Each tile deep-links to its
// tab. Values derive from portalState (DB authority) + chain/findings/ioc slices
// via missionTiles() — no new store keys. Reduced-motion safe throughout.
// ─────────────────────────────────────────────────────────────────────────

const ICONS = { archive: Archive, flame: Flame, crosshair: Crosshair, server: Server }
const TILE_TAB = { evidence: 'evidence', high: 'findings', iocs: 'iocs', backends: 'backends' }

function TileValue({ value }) {
  const numeric = typeof value === 'number'
  const counted = useCountUp(numeric ? value : 0)
  return (
    <span className="tnum font-display text-[26px] font-bold leading-none text-foreground">
      {numeric ? Math.round(counted).toLocaleString() : value}
    </span>
  )
}

function Tile({ tile, onOpen, variants }) {
  const Icon = ICONS[tile.icon] ?? Archive
  const degraded = tile.key === 'backends' && /degraded/.test(tile.foot)
  return (
    <motion.div variants={variants.staggerItem}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Card
            role="button"
            tabIndex={0}
            aria-label={`${tile.label} — ${tile.foot}`}
            onClick={onOpen}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onOpen()
              }
            }}
            className="cursor-pointer gap-2 p-4 transition-shadow hover:ring-2 hover:ring-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
              <TileValue value={tile.value} />
              {tile.sub && <span className="mono text-xs text-muted-foreground">{tile.sub}</span>}
            </div>
            <div className={cn('text-[11px]', tile.tone)}>{tile.foot}</div>
          </Card>
        </TooltipTrigger>
        <TooltipContent>{tile.label}: {tile.foot}</TooltipContent>
      </Tooltip>
    </motion.div>
  )
}

export function MissionStats() {
  const variants = useMotionVariants()
  const { portalState, chainStatus, findings, iocs, setActiveTab } = useStoreSlice((s) => ({
    portalState: s.portalState,
    chainStatus: s.chainStatus,
    findings: s.findings,
    iocs: s.iocs,
    setActiveTab: s.setActiveTab,
  }))

  const tiles = missionTiles(portalState, { chainStatus, findings, iocs })

  return (
    <motion.div
      variants={variants.staggerContainer}
      initial="hidden"
      animate="show"
      className="grid grid-cols-2 gap-4"
    >
      {tiles.map((t) => (
        <Tile key={t.key} tile={t} variants={variants} onOpen={() => navigateToTab(setActiveTab, TILE_TAB[t.key] ?? 'overview')} />
      ))}
    </motion.div>
  )
}
