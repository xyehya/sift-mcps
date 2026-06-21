import { RadarIcon } from 'lucide-react'
import { motion } from 'framer-motion'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { Button } from '@/components/ui/button'
import { HealthPanel } from './HealthPanel'
import { RestartRequiredInline } from './RestartRequiredBanner'
import { BackendRegistryList } from './BackendRegistryList'
import { RegisterBackendForm } from './RegisterBackendForm'
import { BackendChallengeModal } from './BackendChallengeModal'
import { useChallenge } from './useChallenge'
import { useBackends } from './useBackends'

// ─────────────────────────────────────────────────────────────────────────
// BackendsTab — gateway add-on registry console (Mission-Control reskin of the
// legacy backends view, full functional parity). ONE primary scroll owner; a
// flowing page. Top→bottom IA: Header (title + inline restart-required indicator
// + Scan-Backends/reload) → operator health panel → [DB registry list | register
// form]. Every mutating admin action is wrapped in the examiner-password
// challenge (re-verified server-side against Supabase, B-MVP-017).
//
// Decomposed into ≤400-line files: useBackends (registry + form + actions) ·
// useChallenge (re-auth state) · HealthPanel · RestartRequiredBanner ·
// BackendRegistryList + BackendServiceRow · RegisterBackendForm ·
// BackendChallengeModal · backends-utils (pure logic). Mock/real split is at the
// API adapter layer (apiFetch → _mock/routes) — no isMock branching here (§3).
// ─────────────────────────────────────────────────────────────────────────

export function BackendsTab() {
  const variants = useMotionVariants()
  const addToast = useStoreSlice((s) => s.addToast)

  const { modal, openChallenge, closeChallenge, setPassword, submit } = useChallenge()
  const b = useBackends({ addToast, openChallenge })

  const pendingCount = b.backends.filter((x) => x.pending_apply).length

  return (
    <div className="h-full overflow-y-auto">
      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label="Gateway backends and add-ons"
        className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-5"
      >
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border-faint pb-3">
          <div className="flex flex-col gap-1">
            <h1 className="font-display text-[22px] font-bold leading-none tracking-[-0.4px] text-foreground">
              Backends &amp; Add-ons
            </h1>
            <p className="mono text-[10px] uppercase tracking-[.12em] text-muted-foreground">
              Gateway add-on registry · health &amp; lifecycle
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <RestartRequiredInline pendingCount={pendingCount} />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={b.handleReload}
              aria-label="Scan backends — check registry health and apply status"
              className="mono gap-1.5 text-xs"
            >
              <RadarIcon className="size-3.5" aria-hidden />
              Scan Backends
            </Button>
          </div>
        </header>

        <HealthPanel />

        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-3">
          <BackendRegistryList
            backends={b.backends}
            loading={b.loading}
            onToggleEnabled={b.handleToggleEnabled}
            onStart={b.handleStart}
            onStop={b.handleStop}
            onRestart={b.handleRestart}
            onUnregister={b.handleUnregister}
          />

          <RegisterBackendForm
            form={b.form}
            onField={b.setField}
            envActions={b.envActions}
            validating={b.validating}
            onValidate={b.handleValidate}
            onRegister={b.handleRegister}
            validationResult={b.validationResult}
          />
        </div>
      </motion.section>

      <BackendChallengeModal
        modal={modal}
        onChange={setPassword}
        onSubmit={submit}
        onClose={closeChallenge}
      />
    </div>
  )
}
