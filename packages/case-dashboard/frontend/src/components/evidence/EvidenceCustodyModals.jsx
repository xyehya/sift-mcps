// ─────────────────────────────────────────────────────────────────────────
// EvidenceCustodyModals — the chain-of-custody action modals (verify HMAC,
// seal manifest, ignore, delete, retire, re-acquire, unseal). Extracted from
// EvidenceTab to keep file lengths manageable. All data-testids and modal
// IDs are preserved from the original implementation so that EvidenceUnseal
// tests continue to pass — the data-testid attributes must remain unchanged.
// ─────────────────────────────────────────────────────────────────────────

/** Simple password + reason modal shell with Cancel + confirm actions. */
function ModalShell({ title, titleColor, onClose, children }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm">
      <div
        className="w-full max-w-md space-y-4 rounded-xl border p-5"
        style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}
        role="dialog"
        aria-modal="true"
      >
        <h3
          className="font-display font-bold text-base"
          style={{ color: titleColor ?? 'var(--text-bright)' }}
        >
          {title}
        </h3>
        {children}
      </div>
    </div>
  )
}

function PasswordField({ value, onChange, disabled }) {
  return (
    <div className="space-y-1">
      <label
        className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
        htmlFor="custody-modal-password"
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
        className="mono w-full rounded-lg border border-border bg-secondary px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
      />
    </div>
  )
}

function ReasonField({ value, onChange, disabled, placeholder }) {
  return (
    <div className="space-y-1">
      <label
        className="mono block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
        htmlFor="custody-modal-reason"
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
        className="w-full rounded-lg border border-border bg-secondary px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
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
      <div className="mono break-all rounded-lg border border-border bg-secondary px-2 py-1 text-xs text-foreground">
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
  return (
    <div className="mono animate-pulse text-xs text-muted-foreground">{message}</div>
  )
}

function ModalActions({ onClose, closeLabel = 'Cancel', confirmLabel, confirmColor, onConfirm, disabled, formId }) {
  return (
    <div className="flex justify-end gap-2">
      <button
        type="button"
        onClick={onClose}
        className="mono rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {closeLabel}
      </button>
      {confirmLabel && (
        <button
          type={formId ? 'submit' : 'button'}
          form={formId}
          onClick={!formId ? onConfirm : undefined}
          disabled={disabled}
          className="mono rounded-lg px-4 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
          style={confirmColor
            ? { background: `${confirmColor}-dim`, color: `var(${confirmColor})`, border: `1px solid var(${confirmColor})` }
            : { background: 'var(--bg-raised)', border: '1px solid var(--border-hard)', color: 'var(--text-bright)' }}
        >
          {confirmLabel}
        </button>
      )}
    </div>
  )
}

// ── Verify HMAC ──────────────────────────────────────────────────────────
export function VerifyHmacModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Verify Evidence Chain HMAC" onClose={onClose}>
      <p className="text-xs text-muted-foreground">
        Enter password to derive key and verify all manifest entries against the cryptographic verification ledger.
      </p>
      <form id="modal-verify-hmac" onSubmit={onSubmit} className="space-y-4">
        {!result && <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />}
        <ModalError error={error} />
        {loading && <ModalLoading message="Verifying…" />}
        {result && (
          result.ok
            ? <ModalSuccess message={`Verified ${result.verified} event(s). Chain is intact.`} />
            : <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-3 text-xs text-destructive">
                ⚠ {result.failed} event(s) FAILED.
                {result.failed_indices && (
                  <div className="mono mt-1 text-[10px] opacity-80">
                    Indices: {JSON.stringify(result.failed_indices)}
                  </div>
                )}
              </div>
        )}
        <ModalActions
          onClose={onClose}
          closeLabel={result ? 'Close' : 'Cancel'}
          confirmLabel={!result ? 'Verify' : undefined}
          formId="modal-verify-hmac"
          disabled={loading}
          confirmColor="--cyan"
        />
      </form>
    </ModalShell>
  )
}

// ── Seal Manifest ────────────────────────────────────────────────────────
export function SealModal({ password, onPasswordChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Seal Evidence Manifest" onClose={onClose}>
      <p className="text-xs text-muted-foreground">
        Enter password to sign and register all unregistered evidence files into the tamper-evident manifest.
      </p>
      <p className="text-[11px] text-status-pending">
        Large disk/memory images are hashed in full — this can take several minutes.
      </p>
      <form id="modal-seal" onSubmit={onSubmit} className="space-y-4">
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Generating key and signing…" />}
        {result?.sealed && (
          <ModalSuccess message={`Manifest version ${result.manifest_version} sealed successfully!`} />
        )}
        <ModalActions
          onClose={onClose}
          confirmLabel="Confirm"
          formId="modal-seal"
          disabled={loading}
          confirmColor="--jade"
        />
      </form>
    </ModalShell>
  )
}

// ── Ignore ───────────────────────────────────────────────────────────────
export function IgnoreModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Ignore Unregistered File" onClose={onClose}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Marking this file as ignored will exclude it from seal and verification checks.
      </p>
      <form id="modal-ignore" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Temporary scan/log file" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Submitting ignore request…" />}
        {result && <ModalSuccess message="File marked as ignored successfully!" />}
        <ModalActions onClose={onClose} confirmLabel="Ignore File" formId="modal-ignore" disabled={loading} />
      </form>
    </ModalShell>
  )
}

// ── Delete ───────────────────────────────────────────────────────────────
export function DeleteModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Delete Stray File" titleColor="var(--sev-high)" onClose={onClose}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        This <strong className="text-destructive">permanently removes the file's bytes</strong> from the evidence directory.
        The SHA-256 and size are recorded in the append-only custody log.
      </p>
      <form id="modal-delete" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Stray/unauthorized file" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Deleting file…" />}
        {result && <ModalSuccess message="File deleted from evidence." />}
        <ModalActions onClose={onClose} confirmLabel="Delete File" formId="modal-delete" disabled={loading} confirmColor="--sev-high" />
      </form>
    </ModalShell>
  )
}

// ── Retire ───────────────────────────────────────────────────────────────
export function RetireModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Retire Missing File" onClose={onClose}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Retiring a file deactivates its manifest entry. Requires reason and credentials.
      </p>
      <form id="modal-retire" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Formally removed from scope" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Submitting retire request…" />}
        {result && <ModalSuccess message="File retired successfully!" />}
        <ModalActions onClose={onClose} confirmLabel="Retire File" formId="modal-retire" disabled={loading} />
      </form>
    </ModalShell>
  )
}

// ── Re-acquire ───────────────────────────────────────────────────────────
export function ReacquireModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Re-acquire & Re-seal Evidence" titleColor="var(--jade)" onClose={onClose}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Use this when the file's bytes legitimately changed. The prior sealed hash is superseded, not deleted.
      </p>
      <p className="text-[11px] text-status-pending">
        Large images are hashed in full — this can take several minutes.
      </p>
      <form id="modal-reacquire" onSubmit={onSubmit} className="space-y-4">
        <ReasonField value={reason} onChange={onReasonChange} disabled={loading} placeholder="e.g. Original acquisition corrupted; re-imaged" />
        <PasswordField value={password} onChange={onPasswordChange} disabled={loading} />
        <ModalError error={error} />
        {loading && <ModalLoading message="Re-hashing and sealing new manifest version…" />}
        {result && <ModalSuccess message="Evidence re-acquired and re-sealed." />}
        <ModalActions onClose={onClose} confirmLabel="Re-seal" formId="modal-reacquire" disabled={loading} confirmColor="--jade" />
      </form>
    </ModalShell>
  )
}

// ── Unseal (B-MVP-048) ───────────────────────────────────────────────────
export function UnsealModal({ path, password, onPasswordChange, reason, onReasonChange, loading, error, result, onClose, onSubmit }) {
  return (
    <ModalShell title="Unseal Evidence" titleColor="var(--amber)" onClose={onClose}>
      <PathDisplay path={path} />
      <p className="text-xs text-muted-foreground">
        Unsealing <strong className="text-status-pending">clears the immutable flag</strong> on this evidence.
        All agent tools are blocked until you re-seal. This action is recorded in the append-only custody log.
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
          <button
            type="button"
            onClick={onClose}
            className="mono rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Cancel
          </button>
          <button
            type="submit"
            form="modal-unseal"
            data-testid="unseal-submit"
            disabled={loading}
            className="mono rounded-lg px-4 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            style={{ background: 'var(--amber-dim)', color: 'var(--amber)', border: '1px solid var(--amber)' }}
          >
            Unseal
          </button>
        </div>
      </form>
    </ModalShell>
  )
}
