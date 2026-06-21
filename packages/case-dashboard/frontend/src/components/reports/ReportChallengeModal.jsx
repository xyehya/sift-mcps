import { AnimatePresence, motion } from 'framer-motion'
import { ShieldAlert } from 'lucide-react'

import { useMotionVariants } from '@/lib/motion'

// ─────────────────────────────────────────────────────────────────────────
// ReportChallengeModal — examiner password re-auth wrapping report generation
// (F-MVP-4 / B-MVP-017). Report inclusion + export are sensitive human actions:
// the password is re-verified server-side against Supabase, and the server
// records a re-auth audit event for the inclusion. Confirm stays DISABLED until
// a password is entered. Reskinned to the Mission-Control modal shell (spring-in
// + scrim, reduced-motion gated). No secret material is rendered or logged.
// ─────────────────────────────────────────────────────────────────────────

export function ReportChallengeModal({ modal, onChange, onSubmit, onClose }) {
  const variants = useMotionVariants()

  return (
    <AnimatePresence>
      {modal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm">
          <motion.div
            key="report-challenge"
            variants={variants.modal}
            initial="hidden"
            animate="show"
            exit="exit"
            role="dialog"
            aria-modal="true"
            aria-labelledby="report-challenge-title"
            className="w-full max-w-sm space-y-4 rounded-xl border border-border-soft bg-card p-5 shadow-lg"
          >
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-4 shrink-0 text-primary" aria-hidden />
              <h3 id="report-challenge-title" className="font-display text-sm font-bold text-foreground">
                {modal.title}
              </h3>
            </div>

            <p className="text-xs leading-relaxed text-muted-foreground">
              Report inclusion and export are sensitive actions. Re-enter your password to authorize generating
              this report from approved data only.
            </p>

            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-1">
                <label
                  htmlFor="report-challenge-password"
                  className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  Examiner Password
                </label>
                <input
                  id="report-challenge-password"
                  type="password"
                  value={modal.password}
                  onChange={(e) => onChange(e.target.value)}
                  placeholder="Examiner password…"
                  disabled={modal.loading}
                  required
                  autoFocus
                  autoComplete="current-password"
                  className="mono w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              {modal.error && (
                <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 text-xs text-destructive">
                  {modal.error}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  className="mono rounded-lg border border-border-hard px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  data-testid="report-challenge-confirm"
                  disabled={modal.loading || !modal.password}
                  className="mono rounded-lg border border-primary bg-primary/10 px-4 py-1.5 text-xs font-semibold text-primary transition-colors hover:bg-primary/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                >
                  {modal.loading ? 'Authorizing…' : 'Authorize & Generate'}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
