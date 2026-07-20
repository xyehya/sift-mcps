import { AnimatePresence, motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'
import { EvidenceSealModal } from '@/components/evidence/EvidenceSealModal'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceModals — custody actions for seal, disposition, durable recovery,
// and verification. Every mutation has explicit authorization and result states.
//
// Confirm-button tone uses STATIC literal token classes (no interpolation) so
// the Tailwind JIT emits them — never a template-built class name (AGENTS §3/§5).
// ─────────────────────────────────────────────────────────────────────────

// Static tone maps (literal classes only).
const TITLE_TONE = {
  bright: 'text-foreground',
  crimson: 'text-destructive',
  jade: 'text-status-approved',
  amber: 'text-status-pending',
}

const CONFIRM_TONE = {
  primary: 'text-primary border-primary bg-primary/10 hover:bg-primary/20',
  jade: 'text-status-approved border-status-approved bg-status-approved/10 hover:bg-status-approved/20',
  amber: 'text-status-pending border-status-pending bg-status-pending/10 hover:bg-status-pending/20',
  crimson: 'text-destructive border-destructive bg-destructive/10 hover:bg-destructive/20',
  neutral: 'text-foreground border-border-hard bg-bg-raised hover:bg-bg-overlay',
}

// ── Modal shell (motion + scrim) ───────────────────────────────────────────
function ModalShell({ title, titleTone = 'bright', children }) {
  const variants = useMotionVariants()
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm">
      <motion.div
        variants={variants.modal}
        initial="hidden"
        animate="show"
        exit="exit"
        role="dialog"
        aria-modal="true"
        className="w-full max-w-md space-y-4 rounded-xl border border-border-soft bg-card p-5 shadow-lg"
      >
        <h3 className={cn('font-display text-base font-bold', TITLE_TONE[titleTone])}>{title}</h3>
        {children}
      </motion.div>
    </div>
  )
}

function PasswordField({ value, onChange, disabled }) {
  return (
    <div className="space-y-1">
      <label
        htmlFor="custody-modal-password"
        className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
      >
        Examiner Password
      </label>
      <input
        id="custody-modal-password"
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Enter password..."
        disabled={disabled}
        required
        autoComplete="current-password"
        className="mono w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
      />
    </div>
  )
}

function ReasonField({ value, onChange, disabled, placeholder }) {
  return (
    <div className="space-y-1">
      <label
        htmlFor="custody-modal-reason"
        className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
      >
        Justification Reason
      </label>
      <input
        id="custody-modal-reason"
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        required
        className="w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
      />
    </div>
  )
}

function ModalError({ error }) {
  if (!error) return null
  return (
    <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 text-xs text-destructive">
      {error}
    </div>
  )
}

function ModalSuccess({ message }) {
  if (!message) return null
  return (
    <div className="rounded-lg border border-status-approved/20 bg-status-approved/5 p-3 text-xs text-status-approved">
      ✓ {message}
    </div>
  )
}

function ModalLoading({ message }) {
  if (!message) return null
  return <div className="mono animate-pulse text-xs text-muted-foreground">{message}</div>
}

function CancelButton({ onClose, label = 'Cancel' }) {
  return (
    <button
      type="button"
      onClick={onClose}
      className="mono rounded-lg border border-border-hard px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {label}
    </button>
  )
}

function ConfirmButton({ formId, label, tone = 'neutral', disabled, testId }) {
  return (
    <button
      type="submit"
      form={formId}
      data-testid={testId}
      disabled={disabled}
      className={cn(
        'mono rounded-lg border px-4 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50',
        CONFIRM_TONE[tone],
      )}
    >
      {label}
    </button>
  )
}

// ── Full database-custody verification ────────────────────────────────────
function FullVerifyEvidenceModal({ loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Full Verify Evidence">
      <p className="text-xs text-muted-foreground">
        Re-hash every sealed evidence object and verify the active storage profile, source, mount,
        and read-only posture against Postgres custody authority. No new password ceremony is required.
      </p>
      <form id="modal-full-verify" onSubmit={onSubmit} className="space-y-4">
        <ModalError error={error} />
        {loading && <ModalLoading message="Hashing and verifying mounted evidence…" />}
        {result &&
          (result.ok ? (
            <ModalSuccess message="Mounted evidence matches database custody authority." />
          ) : (
            <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-3 text-xs text-destructive">
              ⚠ Full verification failed with {(result.issues || []).length} issue(s).
              {result.issues?.length > 0 && (
                <div className="mono mt-1 text-[10px] opacity-80">
                  {result.issues.join(' · ')}
                </div>
              )}
            </div>
          ))}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} label={result ? 'Close' : 'Cancel'} />
          {!result && <ConfirmButton formId="modal-full-verify" label="Full Verify" tone="primary" disabled={loading} />}
        </div>
      </form>
    </ModalShell>
  )
}

function ResumeSealModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return <ModalShell title="Resume Add & Seal"><p className="text-xs text-muted-foreground">Re-authenticate to resume the server-stored custody operation. No evidence paths or credentials are stored in this page.</p><form id="modal-resume-seal" onSubmit={onSubmit} className="space-y-4"><PasswordField value={password} onChange={onPasswordChange} disabled={loading} /><ModalError error={error} />{loading && <ModalLoading message="Resuming durable custody operation…" />}{result?.sealed && <ModalSuccess message={`Manifest version ${result.manifest_version} sealed successfully!`} />}<div className="flex justify-end gap-2"><CancelButton onClose={onClose} /><ConfirmButton formId="modal-resume-seal" label="Resume" tone="jade" disabled={loading} /></div></form></ModalShell>
}

// ── Resolve (D4 — unified batch, one password/reason, honest verbs) ────────
function ResolveModal({ dispositions, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  const count = dispositions?.length ?? 0
  return (
    <ModalShell title={`Resolve ${count} Finding${count === 1 ? '' : 's'}`}>
      <p className="text-xs text-muted-foreground">
        One password and reason authorizes every selected finding below. Each target keeps its own
        distinct recorded custody verb — this is not a generic bulk action.
      </p>
      <ul className="mono max-h-40 space-y-1 overflow-y-auto rounded-lg border border-border-soft bg-bg-raised p-2 text-[11px]">
        {(dispositions ?? []).map(({ verb, target }) => (
          <li key={target} className="flex items-center justify-between gap-2">
            <span className="break-all text-foreground">{target}</span>
            <span className="shrink-0 font-semibold uppercase tracking-wider text-muted-foreground">{verb}</span>
          </li>
        ))}
      </ul>
      <form id="modal-resolve" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Post-triage disposition" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Resolving selected findings…" />}
        {result && <ModalSuccess message={`Resolved ${result.receipts?.length ?? 0} finding(s).`} />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} label={result ? 'Close' : 'Cancel'} />
          {!result && <ConfirmButton formId="modal-resolve" label="Resolve" tone="primary" disabled={loading} testId="resolve-submit" />}
        </div>
      </form>
    </ModalShell>
  )
}

// ── Dispatcher ─────────────────────────────────────────────────────────────
// One entry point so EvidenceTab stays the orchestrator and modal markup lives
// here. `activeModal` selects which modal renders; AnimatePresence handles the
// spring-in / fade-out (reduced-motion gated via useMotionVariants).
export function EvidenceModals({ activeModal, pendingPath, dispositions, password, reason, loading, error, result, handlers }) {
  const common = {
    path: pendingPath,
    password,
    onPasswordChange: handlers.onPasswordChange,
    reason,
    onReasonChange: handlers.onReasonChange,
    loading,
    error,
    result,
    onClose: handlers.onClose,
  }

  return (
    <AnimatePresence>
      {activeModal === 'full_verify' && (
        <FullVerifyEvidenceModal key="full_verify" {...common} onSubmit={handlers.onFullVerifyEvidence} />
      )}
      {activeModal === 'seal' && <EvidenceSealModal key="seal" {...common} onSubmit={handlers.onSeal} />}
      {activeModal === 'resume_seal' && <ResumeSealModal key="resume_seal" {...common} onSubmit={handlers.onResumeSeal} />}
      {activeModal === 'resolve' && (
        <ResolveModal key="resolve" {...common} dispositions={dispositions} onSubmit={handlers.onResolveFindings} />
      )}
    </AnimatePresence>
  )
}
