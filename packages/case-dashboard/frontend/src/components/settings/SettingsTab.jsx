import { motion } from 'framer-motion'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { usePrincipals } from './usePrincipals'
import { AppearanceSection } from './AppearanceSection'
import { AccountSection } from './AccountSection'
import { IssuedSessionBanner } from './IssuedSessionBanner'
import { IssuePrincipalForm } from './IssuePrincipalForm'
import { PrincipalsTable } from './PrincipalsTable'

// ─────────────────────────────────────────────────────────────────────────
// SettingsTab — operator settings (Mission-Control reskin of the legacy
// 277-line view, full functional parity + the brief's theme/account/RBAC
// surface). ONE primary scroll owner. Top→bottom IA: Appearance (theme via the
// existing lib/theme provider) → Account (RBAC read-out) → Agent/Service JWT
// sessions (issued-once banner → issue form → active-principals table).
//
// RBAC: the issue form + per-row revoke are examiner-only (canWrite); the
// principals table is read-only-visible to all roles. Issuing/revoking a
// credential re-verifies the operator password server-side against Supabase
// (B-MVP-022/CL3b). Token material is held in memory only — never persisted.
//
// Decomposed into <=400-line files: settings-utils (TTL/status + token-class
// maps) · usePrincipals (fetch/create/revoke + TTL clock) · AppearanceSection ·
// AccountSection · IssuedSessionBanner · IssuePrincipalForm · PrincipalsTable.
// Mock/real split is at the API adapter layer — no isMock here (§3).
// ─────────────────────────────────────────────────────────────────────────

export function SettingsTab() {
  const variants = useMotionVariants()
  const { addToast, user } = useStoreSlice((state) => ({
    addToast: state.addToast,
    user: state.user,
  }))
  const canWrite = user?.role === 'examiner'

  const p = usePrincipals({ addToast })

  return (
    <motion.div
      variants={variants.fadeRise}
      initial="hidden"
      animate="show"
      className="h-full space-y-6 overflow-y-auto bg-bg-base p-5"
    >
      <h1 className="font-display text-lg font-bold text-foreground">Settings</h1>

      <AppearanceSection />
      <AccountSection user={user} />

      <div>
        <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Agent / Service JWT Sessions
        </p>

        <IssuedSessionBanner issued={p.issued} nowMs={p.nowMs} onDismiss={p.clearIssued} />

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {canWrite && <IssuePrincipalForm form={p.form} onField={p.setField} onSubmit={p.handleCreate} />}

          <PrincipalsTable
            principals={p.principals}
            loading={p.loading}
            revoking={p.revoking}
            nowMs={p.nowMs}
            onRevoke={canWrite ? p.handleRevoke : undefined}
          />
        </div>
      </div>
    </motion.div>
  )
}
