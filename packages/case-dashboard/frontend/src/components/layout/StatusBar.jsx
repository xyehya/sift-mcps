import { useStoreSlice } from '../../store/useStore'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'

export function StatusBar() {
  const { chainStatus, delta, lastSync, setCommitDrawerOpen, setActiveTab } = useStoreSlice((state) => ({
    chainStatus: state.chainStatus,
    delta: state.delta,
    lastSync: state.lastSync,
    setCommitDrawerOpen: state.setCommitDrawerOpen,
    setActiveTab: state.setActiveTab,
  }))
  const stagedCount = delta.length

  const isSealed = chainStatus && chainStatus.status !== 'unsealed' && chainStatus.manifest_version > 0
  const sealColor = !chainStatus
    ? 'var(--text-muted)'
    : isSealed && !chainStatus.hmac_verify_needed
      ? 'var(--jade)'
      : isSealed
        ? 'var(--amber)'
        : 'var(--crimson)'

  const sealLabel = !chainStatus
    ? 'LOADING'
    : isSealed && !chainStatus.hmac_verify_needed
      ? 'SEALED ✓'
      : isSealed
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
      <button
        onClick={() => setActiveTab('evidence')}
        className="flex items-center gap-1.5 mr-3 px-1 py-0.5 rounded cursor-pointer transition-colors"
        style={{ border: 'none', background: 'none' }}
        title="Go to Evidence tab"
        onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-raised)'}
        onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
      >
        <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: sealColor }} />
        <span style={{ color: sealColor }}>{sealLabel}</span>
      </button>

      <Divider />

      {/* HMAC write-block */}
      {chainStatus?.write_protected && (
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
