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

function StorageProfileModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  const external = path === 'EXTERNALLY_READ_ONLY'
  return (
    <ModalShell title="Change Evidence Storage Profile" titleTone="amber">
      <p className="text-xs text-muted-foreground">
        Change to {external ? 'Externally Read-Only' : 'Local Immutable'}. The custody gate blocks immediately,
        and Full Verify Evidence is required before agent access can resume. Mount identity is observed by the server.
      </p>
      <form id="modal-storage-profile" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="Reason for storage profile change" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Blocking custody gate and changing storage authority…" />}
        {result && <ModalSuccess message="Storage profile changed. Full Verify Evidence is required." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-storage-profile" label="Change Profile" tone="amber" disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

function ResumeDispositionModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return <ModalShell title="Resume Evidence Disposition"><p className="text-xs text-muted-foreground">Re-authenticate to resume the server-stored, gate-blocked disposition. The action and evidence object are selected from the immutable operation record.</p><form id="modal-resume-disposition" onSubmit={onSubmit} className="space-y-4"><PasswordField value={password} onChange={onPasswordChange} disabled={loading} /><ModalError error={error} />{loading && <ModalLoading message="Resuming durable disposition…" />}{result?.success && <ModalSuccess message="Custody disposition completed." />}<div className="flex justify-end gap-2"><CancelButton onClose={onClose} /><ConfirmButton formId="modal-resume-disposition" label="Resume" tone="jade" disabled={loading} /></div></form></ModalShell>
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
function RecoveryBeginModal({ kind, path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  const restore = kind === 'restore'
  return (
    <ModalShell title={restore ? 'Begin Exact Restore' : 'Begin Replace/Reacquire'} titleTone={restore ? 'amber' : 'jade'}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        {restore
          ? 'Use this only to restore the original exact bytes. Completion rejects any hash or size mismatch and does not create a new evidence or manifest version.'
          : 'Use this for a legitimate re-image of the same real-world Evidence Object. Completion requires changed bytes and creates a new Evidence Version while preserving every prior version.'}
        {' '}The custody gate is durably blocked before write protection changes and remains blocked until a separately re-authenticated completion.
      </p>
      <p className="text-[11px] text-status-pending">
        Large disk/memory images are hashed in full — this can take several minutes. Keep this window
        open until it completes.
      </p>
      <form id="modal-recovery-begin" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Original acquisition corrupted; re-imaged from source drive" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Blocking custody gate and recording recovery intent…" />}
        {result && <ModalSuccess message="Recovery intent recorded. Replace or restore the bytes, then use Complete Recovery." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-recovery-begin" label={restore ? 'Begin Exact Restore' : 'Begin Replace/Reacquire'} tone={restore ? 'amber' : 'jade'} disabled={loading} />
        </div>
      </form>
    </ModalShell>
  )
}

function RecoveryCompleteModal({ path, password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Complete Recovery" titleTone="jade">
      <p className="text-xs text-muted-foreground">
        Re-authenticate to hash all mounted bytes, restore immutable posture, and atomically finalize operation <span className="mono">{path}</span>. The custody gate remains blocked on any mismatch or interruption.
      </p>
      <form id="modal-recovery-complete" onSubmit={onSubmit} className="space-y-4">
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Hashing, restoring protection, and committing custody history…" />}
        {result && <ModalSuccess message="Recovery completed and custody gate reopened." />}
        <div className="flex justify-end gap-2">
          <CancelButton onClose={onClose} />
          <ConfirmButton formId="modal-recovery-complete" label="Complete Recovery" tone="jade" disabled={loading} testId="recovery-complete-submit" />
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
      {activeModal === 'full_verify' && (
        <FullVerifyEvidenceModal key="full_verify" {...common} onSubmit={handlers.onFullVerifyEvidence} />
      )}
      {activeModal === 'storage_profile' && (
        <StorageProfileModal key="storage_profile" {...common} onSubmit={handlers.onStorageProfileChange} />
      )}
      {activeModal === 'seal' && <EvidenceSealModal key="seal" {...common} onSubmit={handlers.onSeal} />}
      {activeModal === 'resume_seal' && <ResumeSealModal key="resume_seal" {...common} onSubmit={handlers.onResumeSeal} />}
      {activeModal === 'resume_disposition' && <ResumeDispositionModal key="resume_disposition" {...common} onSubmit={handlers.onDispositionResume} />}
      {activeModal === 'ignore' && <IgnoreModal key="ignore" {...common} onSubmit={handlers.onIgnore} />}
      {activeModal === 'delete' && <DeleteModal key="delete" {...common} onSubmit={handlers.onDelete} />}
      {activeModal === 'retire' && <RetireModal key="retire" {...common} onSubmit={handlers.onRetire} />}
      {activeModal === 'replace' && (
        <RecoveryBeginModal key="replace" kind="replace" {...common} onSubmit={handlers.onReplaceBegin} />
      )}
      {activeModal === 'restore' && (
        <RecoveryBeginModal key="restore" kind="restore" {...common} onSubmit={handlers.onRestoreBegin} />
      )}
      {activeModal === 'complete_recovery' && <RecoveryCompleteModal key="complete_recovery" {...common} onSubmit={handlers.onRecoveryComplete} />}
    </AnimatePresence>
  )
}
