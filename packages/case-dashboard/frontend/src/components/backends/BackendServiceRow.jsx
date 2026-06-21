import { MoreHorizontal, Play, Square, RotateCw, Power, Trash2 } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  getButtonStates,
  hasUnmet,
  healthDotClass,
  healthLabel,
  healthToneClass,
  showsLifecycleButtons,
  statusLabel,
} from './backends-utils'

// ─────────────────────────────────────────────────────────────────────────
// BackendServiceRow — one DB-registry row, rebuilt to the reference table bar
// (Evidence registry). Columns: NAME (Inter body, receding) · TYPE (mono) ·
// STATUS (enabled/disabled chip + status sub-label) · HEALTH (dot + token-toned
// label, detail in tooltip) · REQUIREMENTS (unmet→destructive) · ACTIONS.
//
// ACTIONS is a SINGLE affordance (B8): one primary control (enable-toggle for
// on-demand; Start/Stop for lifecycle backends) + a "⋯" overflow menu holding
// the rest (lifecycle Start/Stop/Restart gated by getButtonStates/showsLifecycle,
// enable-toggle, Unregister). Every mutating item still routes through the
// challenge-gated handlers unchanged. All colour via literal token classes.
// ─────────────────────────────────────────────────────────────────────────

/** Enabled / Disabled registry chip — pill matching the bar's badge treatment. */
function EnabledChip({ enabled }) {
  return enabled ? (
    <span className="mono rounded-full border border-status-approved/40 bg-status-approved/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] text-status-approved">
      Enabled
    </span>
  ) : (
    <span className="mono rounded-full border border-border-soft bg-secondary px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
      Disabled
    </span>
  )
}

/** Status sub-label under the enabled chip (pending / on-demand / started). */
function StatusSubLabel({ backend }) {
  const label = statusLabel(backend)
  const tone =
    label === 'Pending restart'
      ? 'text-status-pending'
      : label === 'Ready · on-demand' || label === 'Started'
        ? 'text-status-approved'
        : 'text-muted-foreground'
  return (
    <span
      className={cn('mono text-[11px]', tone)}
      title={
        backend.on_demand
          ? 'FastMCP proxy mounted; the subprocess spawns on demand per call.'
          : undefined
      }
    >
      {label}
    </span>
  )
}

export function BackendServiceRow({
  backend,
  onToggleEnabled,
  onStart,
  onStop,
  onRestart,
  onUnregister,
}) {
  const status = backend.health?.status || 'unknown'
  const unmet = hasUnmet(backend)
  const { canStart, canStop, canRestart } = getButtonStates(backend)
  const lifecycle = showsLifecycleButtons(backend)

  return (
    <tr className="text-foreground transition-colors hover:bg-secondary/40">
      {/* NAME — Inter body, receding (NOT mono title-weight) */}
      <td className="px-3 py-2.5 align-middle text-[13px] font-medium text-foreground">
        {backend.name}
      </td>

      {/* TYPE — mono */}
      <td className="mono px-3 py-2.5 align-middle text-[11px] text-muted-foreground">
        {backend.type}
      </td>

      {/* STATUS */}
      <td className="px-3 py-2.5 align-middle">
        <div className="flex flex-col items-start gap-1">
          <EnabledChip enabled={backend.enabled} />
          <StatusSubLabel backend={backend} />
        </div>
      </td>

      {/* HEALTH — dot + token-toned label */}
      <td className="px-3 py-2.5 align-middle">
        <span
          className="inline-flex items-center gap-1.5"
          title={backend.health?.detail || ''}
        >
          <span
            className={cn('inline-block size-2 shrink-0 rounded-full', healthDotClass(status))}
            aria-hidden
          />
          <span className={cn('mono text-[11px] font-semibold', healthToneClass(status))}>
            {healthLabel(status)}
          </span>
        </span>
      </td>

      {/* REQUIREMENTS */}
      <td className="max-w-[200px] px-3 py-2.5 align-middle text-[11px] leading-relaxed">
        {unmet ? (
          <span className="font-semibold text-destructive">
            Unmet: {backend.unmet_requires.join(', ')}
          </span>
        ) : backend.requires && backend.requires.length > 0 ? (
          <span className="text-muted-foreground">Requires: {backend.requires.join(', ')}</span>
        ) : (
          <span className="italic text-muted-foreground">None</span>
        )}
      </td>

      {/* ACTIONS — single affordance: one primary + ⋯ overflow menu */}
      <td className="px-3 py-2.5 text-right align-middle">
        <RowActions
          backend={backend}
          lifecycle={lifecycle}
          canStart={canStart}
          canStop={canStop}
          canRestart={canRestart}
          onToggleEnabled={onToggleEnabled}
          onStart={onStart}
          onStop={onStop}
          onRestart={onRestart}
          onUnregister={onUnregister}
        />
      </td>
    </tr>
  )
}

/**
 * Single-affordance row actions: a primary button + a "⋯" overflow menu.
 * Lifecycle backends → primary is Start (when stoppable) / Stop (when running);
 * on-demand backends have no manual lifecycle, so the primary is the enable
 * toggle. The overflow menu holds the remaining lifecycle controls (gated by
 * the same canStart/canStop/canRestart), the enable toggle, and Unregister.
 */
function RowActions({
  backend,
  lifecycle,
  canStart,
  canStop,
  canRestart,
  onToggleEnabled,
  onStart,
  onStop,
  onRestart,
  onUnregister,
}) {
  const name = backend.name
  const toggleEnabled = () => onToggleEnabled(name, !backend.enabled)

  // Primary affordance.
  let primary
  if (lifecycle && backend.started) {
    primary = (
      <ActionButton
        label="Stop"
        icon={Square}
        disabled={!canStop}
        tone="destructive"
        onClick={() => onStop(name)}
      />
    )
  } else if (lifecycle) {
    primary = (
      <ActionButton
        label="Start"
        icon={Play}
        disabled={!canStart}
        tone="approved"
        onClick={() => onStart(name)}
      />
    )
  } else {
    primary = (
      <ActionButton
        label={backend.enabled ? 'Disable' : 'Enable'}
        icon={Power}
        tone={backend.enabled ? 'muted' : 'approved'}
        onClick={toggleEnabled}
      />
    )
  }

  return (
    <div className="inline-flex items-center gap-1.5">
      {primary}

      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label={`More actions for ${name}`}
                className="mono inline-flex size-7 items-center justify-center rounded border border-border-soft text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                <MoreHorizontal className="size-4" aria-hidden />
              </button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent>More actions</TooltipContent>
        </Tooltip>

        <DropdownMenuContent align="end" className="min-w-[12rem]">
          {lifecycle && (
            <>
              <DropdownMenuItem disabled={!canStart} onSelect={() => onStart(name)} className="gap-2">
                <Play className="size-4" aria-hidden />
                Start service
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!canStop} onSelect={() => onStop(name)} className="gap-2">
                <Square className="size-4" aria-hidden />
                Stop service
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!canRestart} onSelect={() => onRestart(name)} className="gap-2">
                <RotateCw className="size-4" aria-hidden />
                Restart service
              </DropdownMenuItem>
              <DropdownMenuSeparator />
            </>
          )}

          <DropdownMenuItem onSelect={toggleEnabled} className="gap-2">
            <Power className="size-4" aria-hidden />
            {backend.enabled ? 'Disable backend' : 'Enable backend'}
          </DropdownMenuItem>

          <DropdownMenuSeparator />

          <DropdownMenuItem
            variant="destructive"
            onSelect={() => onUnregister(name)}
            className="gap-2"
          >
            <Trash2 className="size-4" aria-hidden />
            Unregister
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}

const TONE_CLS = {
  approved:
    'border-status-approved/40 bg-status-approved/10 text-status-approved hover:bg-status-approved/20',
  destructive:
    'border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20',
  muted: 'border-border-soft bg-secondary text-muted-foreground hover:text-foreground',
}

/** Small token-toned primary action button (one per row). */
function ActionButton({ label, icon: Icon, tone, disabled, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className={cn(
        'mono inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-40',
        TONE_CLS[tone],
      )}
    >
      <Icon className="size-3" aria-hidden />
      {label}
    </button>
  )
}
