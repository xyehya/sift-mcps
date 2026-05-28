import { useStore } from '../../store/useStore'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'

export function StatusBar() {
  const { chainStatus, delta, lastSync, user, setCommitDrawerOpen } = useStore()
  const stagedCount = delta.length

  const sealColor = !chainStatus
    ? 'var(--text-muted)'
    : chainStatus.sealed && chainStatus.hmac_verified
      ? 'var(--jade)'
      : chainStatus.sealed
        ? 'var(--amber)'
        : 'var(--crimson)'

  const sealLabel = !chainStatus
    ? 'LOADING'
    : chainStatus.sealed && chainStatus.hmac_verified
      ? 'SEALED ✓'
      : chainStatus.sealed
        ? 'SEALED · verify pending'
        : 'UNSEALED'

  const syncLabel = lastSync
    ? 'sync ' + formatDistanceToNow(lastSync, { addSuffix: true })
    : 'syncing…'

  return (
    <div
      className="flex items-center h-[32px] px-4 text-xs font-mono shrink-0 select-none z-20"
      style={{
        background: 'var(--bg-surface)',
        borderTop: '1px solid var(--border-faint)',
        color: 'var(--text-muted)',
      }}
    >
      {/* Seal status */}
      <span className="flex items-center gap-1.5 mr-3">
        <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: sealColor }} />
        <span style={{ color: sealColor }}>{sealLabel}</span>
      </span>

      <Divider />

      {/* HMAC write-block */}
      {chainStatus?.write_blocked && (
        <>
          <span style={{ color: 'var(--cyan)' }}>write-protected</span>
          <Divider />
        </>
      )}

      {/* Staged count */}
      <span
        className={clsx(stagedCount > 0 && 'pulse')}
        style={{ color: stagedCount > 0 ? 'var(--amber)' : 'var(--text-muted)' }}
      >
        {stagedCount > 0 ? `${stagedCount} staged` : 'no staged changes'}
      </span>

      <Divider />

      {/* Sync time */}
      <span>{syncLabel}</span>

      {/* Examiner */}
      {user && (
        <>
          <Divider />
          <span style={{ color: 'var(--text-muted)' }}>{user.examiner}</span>
        </>
      )}

      <div className="flex-1" />

      {/* Commit button — only clickable when staged */}
      {stagedCount > 0 && (
        <button
          onClick={(e) => { e.stopPropagation(); setCommitDrawerOpen(true) }}
          className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-sans font-semibold cursor-pointer hover:opacity-80 transition-opacity"
          style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}
          title="Open commit drawer"
        >
          ↑ COMMIT
        </button>
      )}
    </div>
  )
}

function Divider() {
  return <span className="mx-2" style={{ color: 'var(--border-hard)' }}>·</span>
}
