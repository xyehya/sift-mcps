import { cn } from '@/lib/utils'
import {
  getButtonStates,
  hasUnmet,
  healthLabel,
  healthToneClass,
  showsLifecycleButtons,
  statusLabel,
} from './backends-utils'

// ─────────────────────────────────────────────────────────────────────────
// BackendServiceRow — one DB-registry row (legacy IA parity §4). Columns:
// NAME · TYPE · STATUS (enabled/disabled chip + pending/on-demand/started/
// stopped sub-label) · HEALTH (ok/disabled/gated/invalid_manifest/unknown,
// detail in tooltip) · REQUIREMENTS (unmet→crimson, else requires/None) ·
// ACTIONS (enable-toggle · Start/Stop/Restart gated on canStart/Stop/Restart
// AND hidden when on_demand · Unregister). All colour via literal token classes.
// ─────────────────────────────────────────────────────────────────────────

const ACTION_BTN =
  'mono rounded border px-2 py-0.5 text-[10px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-40 disabled:pointer-events-none'

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
      className={cn('ml-2 text-xs', tone)}
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

export function BackendServiceRow({ backend, onToggleEnabled, onStart, onStop, onRestart, onUnregister }) {
  const status = backend.health?.status || 'unknown'
  const unmet = hasUnmet(backend)
  const { canStart, canStop, canRestart } = getButtonStates(backend)

  return (
    <tr className="border-b border-border-faint text-foreground">
      <td className="mono py-3 font-semibold">{backend.name}</td>
      <td className="mono py-3 text-[11px] text-muted-foreground">{backend.type}</td>
      <td className="py-3">
        {backend.enabled ? (
          <span className="mono rounded bg-status-approved/10 px-1.5 py-0.5 text-[9px] font-semibold text-status-approved">
            ENABLED
          </span>
        ) : (
          <span className="mono rounded bg-bg-raised px-1.5 py-0.5 text-[9px] font-semibold text-muted-foreground">
            DISABLED
          </span>
        )}
        <StatusSubLabel backend={backend} />
      </td>
      <td className="py-3">
        <span
          className={cn('mono text-xs font-semibold', healthToneClass(status))}
          title={backend.health?.detail || ''}
        >
          {healthLabel(status)}
        </span>
      </td>
      <td className="max-w-[200px] py-3 text-xs leading-relaxed">
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
      <td className="space-x-1.5 py-3 text-right">
        <button
          type="button"
          onClick={() => onToggleEnabled(backend.name, !backend.enabled)}
          className={cn(
            ACTION_BTN,
            backend.enabled
              ? 'border-border-soft bg-bg-raised text-muted-foreground hover:text-foreground'
              : 'border-status-approved bg-status-approved/10 text-status-approved hover:bg-status-approved/20',
          )}
          title={
            backend.enabled
              ? 'Disable this backend (registry row)'
              : 'Enable this backend (registry row)'
          }
        >
          {backend.enabled ? 'Disable' : 'Enable'}
        </button>

        {showsLifecycleButtons(backend) ? (
          <>
            <button
              type="button"
              onClick={() => onStart(backend.name)}
              disabled={!canStart}
              className={cn(
                ACTION_BTN,
                'border-status-approved bg-status-approved/10 text-status-approved hover:bg-status-approved/20',
              )}
            >
              Start
            </button>
            <button
              type="button"
              onClick={() => onStop(backend.name)}
              disabled={!canStop}
              className={cn(
                ACTION_BTN,
                'border-destructive bg-destructive/10 text-destructive hover:bg-destructive/20',
              )}
            >
              Stop
            </button>
            <button
              type="button"
              onClick={() => onRestart(backend.name)}
              disabled={!canRestart}
              className={cn(
                ACTION_BTN,
                'border-status-pending bg-status-pending/10 text-status-pending hover:bg-status-pending/20',
              )}
            >
              Restart
            </button>
          </>
        ) : (
          <span
            className="mono mr-1 text-[10px] italic text-muted-foreground"
            title="On-demand (proxy-mounted): the subprocess spawns per call. Manual start/stop/restart do not apply."
          >
            on-demand
          </span>
        )}

        <button
          type="button"
          onClick={() => onUnregister(backend.name)}
          className={cn(
            ACTION_BTN,
            'border-destructive bg-destructive/10 text-destructive hover:bg-destructive/20',
          )}
        >
          Unregister
        </button>
      </td>
    </tr>
  )
}
