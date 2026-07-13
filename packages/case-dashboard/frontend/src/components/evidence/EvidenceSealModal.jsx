import { motion } from 'framer-motion'

import { useMotionVariants } from '@/lib/motion'

export function EvidenceSealModal({ password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  const variants = useMotionVariants()
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm">
      <motion.div variants={variants.modal} initial="hidden" animate="show" exit="exit" role="dialog" aria-modal="true" className="w-full max-w-md space-y-4 rounded-xl border border-border-soft bg-card p-5 shadow-lg">
        <h3 className="font-display text-base font-bold text-foreground">Seal Evidence Manifest</h3>
        <p className="text-xs text-muted-foreground">
          Re-authenticate to register all pending evidence files in a new tamper-evident manifest.
        </p>
        <p className="text-[11px] text-status-pending">
          Large disk/memory images are hashed in full — this can take several minutes. Keep this window open until it completes.
        </p>
        <form id="modal-seal" onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1">
            <label htmlFor="custody-modal-reason" className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Justification Reason</label>
            <input id="custody-modal-reason" type="text" value={reason} onChange={(e) => onReasonChange(e.target.value)} placeholder="e.g. Initial evidence intake from validated source" disabled={loading} required className="w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring" />
          </div>
          <div className="space-y-1">
            <label htmlFor="custody-modal-password" className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Examiner Password</label>
            <input id="custody-modal-password" type="password" value={password} onChange={(e) => onPasswordChange(e.target.value)} placeholder="Enter password..." disabled={loading} required autoComplete="current-password" className="mono w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring" />
          </div>
          {error && <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 text-xs text-destructive">{error}</div>}
          {loading && <div className="mono animate-pulse text-xs text-muted-foreground">Hashing, hardening, and committing custody records…</div>}
          {result?.sealed && <div className="rounded-lg border border-status-approved/20 bg-status-approved/5 p-3 text-xs text-status-approved">✓ Manifest version {result.manifest_version} sealed successfully!</div>}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="mono rounded-lg border border-border-hard px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">Cancel</button>
            <button type="submit" form="modal-seal" disabled={loading} className="mono rounded-lg border border-status-approved bg-status-approved/10 px-4 py-1.5 text-xs font-semibold text-status-approved transition-colors hover:bg-status-approved/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50">Confirm</button>
          </div>
        </form>
      </motion.div>
    </div>
  )
}
