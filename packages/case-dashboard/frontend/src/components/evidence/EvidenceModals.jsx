import { AnimatePresence, motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceModals — the 7 chain-of-custody action modals (legacy IA parity §7):
// verify_hmac · seal · ignore · delete · retire · reacquire · unseal. Each has
// an examiner password field; ignore/delete/retire/reacquire/unseal also carry
// a justification reason field. All preserve the legacy explanatory copy and
// error / loading / result states. data-testid="unseal-submit" is preserved on
// the unseal confirm button (frozen EvidenceUnseal.test.jsx).
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

function PathDisplay({ path }) {
  return (
    <div className="space-y-1">
      <span className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Target File Path
      </span>
      <div className="mono break-all rounded-lg border border-border-soft bg-bg-raised px-2 py-1 text-xs text-foreground">
        {path}
      </div>
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

// ── Verify HMAC ────────────────────────────────────────────────────────────
function VerifyHmacModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Verify Evidence Chain HMAC">
      <p className="text-xs text-muted-foreground">
        Enter password to derive key and verify all manifest entries against the cryptographic
        verification ledger.
      </p>
      <form id="modal-verify-hmac" onSubmit={onSubmit} className="space-y-4">
        {!result && <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />}
        <ModalError error={error} />
        {loading && <ModalLoading message="Verifying…" />}
        {result &&
          (result.ok ? (
            <ModalSuccess message={`Verified ${result.verified} event(s). Chain is intact.`} />
          ) : (
            <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-3 text-xs text-destructive">
              ⚠ {result.failed} event(s) FAILED.
              {result.failed_indices && (
                <div className="mono mt-1 text-[10px] opacity-80">
                  Indices: {JSON.stringify(result.failed_indices)}
                </div>
              )}
            </div>
          ))}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} label={result ? 'Close' : 'Cancel'} />
          {!result && <ConfirmButton formId="modal-verify-hmac" label="Verify" tone="primary" disabled={loading} />}
        </div>
      </form>
    </ModalShell>
  )
}

// ── Seal Manifest ──────────────────────────────────────────────────────────
function SealModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Seal Evidence Manifest">
      <p className="text-xs text-muted-foreground">
        Enter password to sign and register all unregistered evidence files into the tamper-evident
        manifest.
      </p>
      <p className="text-[11px] text-status-pending">
        Large disk/memory images are hashed in full — this can take several minutes. Keep this window
        open until it completes.
      </p>
      <form id="modal-seal" onSubmit={onSubmit} className="space-y-4">
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Generating key and signing…" />}
        {result?.sealed && (
          <ModalSuccess message={`Manifest version ${result.manifest_version} sealed successfully!`} />
        )}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-seal" label="Confirm" tone="jade" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Ignore ─────────────────────────────────────────────────────────────────
function IgnoreModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Ignore Unregistered File">
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Marking this file as ignored will exclude it from seal and verification checks. This action
        requires examiner justification and credentials.
      </p>
      <form id="modal-ignore" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Temporary scan/log file" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Submitting ignore request…" />}
        {result && <ModalSuccess message="File marked as ignored successfully!" />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-ignore" label="Ignore File" tone="neutral" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Delete ─────────────────────────────────────────────────────────────────
function DeleteModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Delete Stray File" titleTone="crimson">
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        This <strong className="text-destructive">permanently removes the file&apos;s bytes</strong> from the
        evidence directory so it can no longer be read or indexed by the AI agent. Sealed evidence
        cannot be deleted. The removed file&apos;s SHA-256 and size are recorded in the append-only custody
        log. This action requires examiner justification and credentials.
      </p>
      <form id="modal-delete" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Stray/unauthorized file, not part of acquisition" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Deleting file…" />}
        {result && <ModalSuccess message="File deleted from evidence." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-delete" label="Delete File" tone="crimson" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Retire ─────────────────────────────────────────────────────────────────
function RetireModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Retire Missing File">
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Retiring a file will deactivate its entry in the manifest. The file will no longer be expected
        during checks. This requires reason and credentials.
      </p>
      <form id="modal-retire" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Formally removed from scope" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Submitting retire request…" />}
        {result && <ModalSuccess message="File retired successfully!" />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-retire" label="Retire File" tone="neutral" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Re-acquire (Re-seal) ───────────────────────────────────────────────────
function ReacquireModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Re-acquire & Re-seal Evidence" titleTone="jade">
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Use this when the file&apos;s bytes legitimately changed (e.g. a corrupted acquisition was
        re-imaged). The replacement on disk is re-hashed in full and a new manifest version is sealed;
        the <strong className="text-foreground">previous sealed hash is superseded, not deleted</strong> — the
        old hash, new hash, and your justification are recorded in the append-only custody ledger. This
        clears the chain-of-custody violation. Requires examiner justification and credentials.
      </p>
      <p className="text-[11px] text-status-pending">
        Large disk/memory images are hashed in full — this can take several minutes. Keep this window
        open until it completes.
      </p>
      <form id="modal-reacquire" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Original acquisition corrupted; re-imaged from source drive" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Re-hashing replacement and sealing new manifest version…" />}
        {result && <ModalSuccess message="Evidence re-acquired and re-sealed." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-reacquire" label="Re-seal" tone="jade" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Unseal (B-MVP-048) ─────────────────────────────────────────────────────
function UnsealModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Unseal Evidence" titleTone="amber">
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Unsealing <strong className="text-status-pending">clears the immutable (write-protection) flag</strong> on
        this evidence so you can replace, re-image, or add evidence. The case becomes{' '}
        <strong className="text-foreground">non-sealed</strong> and{' '}
        <strong className="text-status-pending">all agent tools are blocked until you re-seal</strong>. This action
        is recorded in the append-only custody log and requires examiner justification and credentials.
        Re-seal as soon as your changes are complete.
      </p>
      <form id="modal-unseal" onSubmit={onSubmit} className="space-y-4">
        <ReasonField
          value={reason}
          onChange={onReasonChange}
          disabled={loading}
          placeholder="e.g. Replacing corrupted image / adding newly acquired evidence"
        />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Submitting unseal request…" />}
        {result && <ModalSuccess message="Evidence unsealed. Re-seal before agent tools can run." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-unseal" label="Unseal" tone="amber" disabled={loading} testId="unseal-submit" />
        </div>
      </form>
    </ModalShell>
  )
}

// ── Dispatcher ─────────────────────────────────────────────────────────────
// One entry point so EvidenceTab stays the orchestrator and modal markup lives
// here. `activeModal` selects which modal renders; AnimatePresence handles the
// spring-in / fade-out (reduced-motion gated via useMotionVariants).
export function EvidenceModals({ activeModal, pendingPath, password, reason, loading, error, result, handlers }) {
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
      {activeModal === 'verify_hmac' && (
        <VerifyHmacModal key="verify_hmac" {...common} onSubmit={handlers.onVerifyHmac} />
      )}
      {activeModal === 'seal' && <SealModal key="seal" {...common} onSubmit={handlers.onSeal} />}
      {activeModal === 'ignore' && <IgnoreModal key="ignore" {...common} onSubmit={handlers.onIgnore} />}
      {activeModal === 'delete' && <DeleteModal key="delete" {...common} onSubmit={handlers.onDelete} />}
      {activeModal === 'retire' && <RetireModal key="retire" {...common} onSubmit={handlers.onRetire} />}
      {activeModal === 'reacquire' && (
        <ReacquireModal key="reacquire" {...common} onSubmit={handlers.onReacquire} />
      )}
      {activeModal === 'unseal' && <UnsealModal key="unseal" {...common} onSubmit={handlers.onUnseal} />}
    </AnimatePresence>
  )
}
