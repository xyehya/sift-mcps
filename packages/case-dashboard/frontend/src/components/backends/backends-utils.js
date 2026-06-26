// ─────────────────────────────────────────────────────────────────────────
// Backends — pure helpers + token-class maps (no JSX, no store). Kept in a
// .js module so the component files stay clean under react-refresh's
// only-export-components rule, and so the registry/lifecycle logic is
// unit-testable in isolation (BackendsTab.test.jsx asserts these directly).
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits
// it. Never build a token class by interpolation — it won't generate.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Parse the register-form arguments textarea into an args array. Two accepted
 * forms (legacy parity):
 *   • a JSON array literal — `["--verbose", "--port", "8080"]`
 *   • a newline-separated list — one arg per line, trimmed, blanks dropped
 * A malformed JSON array (starts `[` ends `]` but won't parse, or parses to a
 * non-array) FALLS BACK to the newline split — so `'["a", "b"'` (no closing
 * bracket) is treated as a single-line list `['["a", "b"']`.
 */
export function parseArgs(argsStr) {
  let parsedArgs = []
  const trimmed = (argsStr ?? '').trim()
  if (trimmed) {
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        parsedArgs = JSON.parse(trimmed)
        if (!Array.isArray(parsedArgs)) {
          throw new Error('Args JSON must be an array')
        }
      } catch {
        parsedArgs = trimmed.split('\n').map((a) => a.trim()).filter(Boolean)
      }
    } else {
      parsedArgs = trimmed.split('\n').map((a) => a.trim()).filter(Boolean)
    }
  }
  return parsedArgs
}

/**
 * Compile the env-var reference grid (a list of {key, value} rows) into a flat
 * record. Legacy parity: BOTH key and value are trimmed, and a row is dropped
 * unless its trimmed key AND trimmed value are non-empty (these are Gateway
 * env-var NAMES referenced by the backend, never secret material).
 */
export function compileEnv(envList) {
  const envObj = {}
  ;(envList ?? []).forEach(({ key, value }) => {
    if (key.trim() && value.trim()) {
      envObj[key.trim()] = value.trim()
    }
  })
  return envObj
}

/**
 * Lifecycle-button enablement for a registry row. Start requires the backend
 * be enabled, stopped, and have all requirements met. Stop is allowed whenever
 * the service is started (even if disabled or newly gated — you must be able to
 * stop a running process). Restart requires enabled + started + met.
 */
export function getButtonStates(backend) {
  const hasUnmet = backend.unmet_requires && backend.unmet_requires.length > 0
  return {
    canStart: !!(backend.enabled && !backend.started && !hasUnmet),
    canStop: !!backend.started,
    canRestart: !!(backend.enabled && backend.started && !hasUnmet),
  }
}

/**
 * Whether a registry row shows manual Start/Stop/Restart controls. On-demand
 * (proxy-mounted) backends lazy-spawn per call, so manual lifecycle controls
 * are meaningless and hidden (XYE-44).
 */
export function showsLifecycleButtons(backend) {
  return !backend.on_demand
}

/** Whether a backend has unmet requirements. */
export function hasUnmet(backend) {
  return !!(backend.unmet_requires && backend.unmet_requires.length > 0)
}

/**
 * The STATUS sub-label for a registry row. Pending-restart wins over all;
 * on-demand reads "Ready · on-demand" (never "Stopped"); else started/stopped.
 */
export function statusLabel(b) {
  return b.pending_apply
    ? 'Pending restart'
    : b.on_demand
      ? 'Ready · on-demand'
      : b.started
        ? 'Started'
        : 'Stopped'
}

// ── Health-status → token text-colour class (literal map; JIT-safe) ──────────
const HEALTH_TONE = {
  ok: 'text-status-approved',
  disabled: 'text-muted-foreground',
  gated: 'text-status-pending',
  warning: 'text-status-pending',
  stopped: 'text-muted-foreground',
  error: 'text-destructive',
  invalid_manifest: 'text-destructive',
  unknown: 'text-muted-foreground',
}

/** Token text-colour class for a health status string. */
export function healthToneClass(status) {
  return HEALTH_TONE[status] || 'text-muted-foreground'
}

// ── Health-status → status-dot background class (literal map; JIT-safe) ──────
const HEALTH_DOT = {
  ok: 'bg-status-approved',
  disabled: 'bg-muted-foreground',
  gated: 'bg-status-pending',
  warning: 'bg-status-pending',
  stopped: 'bg-muted-foreground',
  error: 'bg-destructive',
  invalid_manifest: 'bg-destructive',
  unknown: 'bg-muted-foreground',
}

/** Token background class for a health status dot. */
export function healthDotClass(status) {
  return HEALTH_DOT[status] || 'bg-muted-foreground'
}

/** Human-readable health label for the registry HEALTH column. */
export function healthLabel(status) {
  if (status === 'ok') return 'OK'
  if (status === 'disabled') return 'Disabled'
  if (status === 'gated') return 'Gated'
  if (status === 'invalid_manifest') return 'Invalid Manifest'
  return status || 'unknown'
}

/**
 * Build the register payload `config` object from form state (legacy parity).
 * stdio → command + parsed args + env_refs record; http → url + optional
 * bearer/tls env-var references. Pure: takes form values, returns config.
 */
export function buildConfigPayload(form) {
  const { type, manifestPath, command, argsStr, envList, url, bearerTokenEnv, tlsCertEnv } = form
  const config = { type, manifest_path: manifestPath }
  if (type === 'stdio') {
    config.command = command
    config.args = parseArgs(argsStr)
    config.env_refs = compileEnv(envList)
  } else {
    config.url = url
    if (bearerTokenEnv) config.bearer_token_env = bearerTokenEnv
    if (tlsCertEnv) config.tls_cert_env = tlsCertEnv
  }
  return config
}
