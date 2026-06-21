import { CheckCircle2, AlertTriangle, Loader2, Plus, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// RegisterBackendForm — the "Register new backend" panel (legacy IA parity §5):
// transport type · name · manifest path/url · stdio (command · args textarea ·
// env-var-reference grid) OR http (url · bearer-token-env · tls-cert-env) ·
// Validate · Register (challenge-gated upstream). Plus the validation-result
// card (valid → namespace/provides/requires/tools/instructions; invalid →
// reasons). The arg-parse / env-compile semantics live in backends-utils and
// are applied by the parent on submit. Reskinned to orange/graphite tokens.
// ─────────────────────────────────────────────────────────────────────────

const FIELD =
  'w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring'
const FIELD_LABEL = 'mono mb-1 block text-[10px] text-muted-foreground'

function ValidationResult({ result }) {
  if (!result) return null
  const valid = !!result.valid
  return (
    <div
      className={cn(
        'space-y-3 rounded-lg border p-4 text-xs',
        valid
          ? 'border-status-approved/40 bg-status-approved/5'
          : 'border-destructive/40 bg-destructive/5',
      )}
    >
      <div
        className={cn(
          'flex items-center gap-1.5 font-bold',
          valid ? 'text-status-approved' : 'text-destructive',
        )}
      >
        {valid ? (
          <>
            <CheckCircle2 className="size-4" aria-hidden /> VALID BACKEND MANIFEST
          </>
        ) : (
          <>
            <AlertTriangle className="size-4" aria-hidden /> VALIDATION ERROR
          </>
        )}
      </div>

      {valid ? (
        <div className="space-y-2 text-foreground">
          <div>
            <span className="mono block text-[10px] uppercase text-muted-foreground">Namespace</span>
            <span className="mono font-semibold">{result.namespace}</span>
          </div>
          <div>
            <span className="mono block text-[10px] uppercase text-muted-foreground">
              Provides Capabilities
            </span>
            <span>{result.provides?.join(', ') || 'none'}</span>
          </div>
          <div>
            <span className="mono block text-[10px] uppercase text-muted-foreground">
              Requirements
            </span>
            {result.unmet_requires?.length > 0 ? (
              <span className="font-semibold text-destructive">
                Unmet: {result.unmet_requires.join(', ')}
              </span>
            ) : (
              <span className="text-muted-foreground">
                {result.requires?.join(', ') || 'none'} (all met)
              </span>
            )}
          </div>
          {result.tools && result.tools.length > 0 && (
            <div>
              <span className="mono block text-[10px] uppercase text-muted-foreground">
                Registered Tools ({result.tools.length})
              </span>
              <ul className="mono mt-1 max-h-[120px] list-inside list-disc space-y-1 overflow-y-auto pl-1 text-[11px]">
                {result.tools.map((t, idx) => (
                  <li key={idx} title={t.description || ''}>
                    {t.name}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.instructions && (
            <div>
              <span className="mono block text-[10px] uppercase text-muted-foreground">
                Instructions
              </span>
              <p className="mono mt-1 max-h-[100px] overflow-y-auto whitespace-pre-wrap rounded bg-bg-raised/60 p-2 text-[11px] leading-relaxed">
                {result.instructions}
              </p>
            </div>
          )}
        </div>
      ) : (
        <ul className="mono list-inside list-disc space-y-1 text-[11px] leading-relaxed text-foreground">
          {result.reasons?.map((r, i) => (
            <li key={i}>
              <strong className="text-foreground">{r.field}:</strong> {r.reason}
            </li>
          )) || <li>Unknown validation error occurred</li>}
        </ul>
      )}
    </div>
  )
}

export function RegisterBackendForm({ form, onField, envActions, validating, onValidate, onRegister, validationResult }) {
  const { type, name, manifestPath, command, argsStr, envList, url, bearerTokenEnv, tlsCertEnv } = form

  return (
    <div className="space-y-6 lg:col-span-1">
      <div className="flex flex-col rounded-lg border border-border-soft bg-card p-4">
        <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Register New Backend
        </p>

        <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
          <div>
            <label htmlFor="reg-type" className={FIELD_LABEL}>
              TRANSPORT TYPE
            </label>
            <select
              id="reg-type"
              value={type}
              onChange={(e) => onField('type', e.target.value)}
              className={cn(FIELD, 'cursor-pointer')}
            >
              <option value="stdio">stdio (Local Subprocess)</option>
              <option value="http">http (Remote/Local HTTP Endpoint)</option>
            </select>
          </div>

          <div>
            <label htmlFor="reg-name" className={FIELD_LABEL}>
              BACKEND NAME *
            </label>
            <input
              id="reg-name"
              type="text"
              placeholder="e.g. windows-triage-mcp"
              value={name}
              onChange={(e) => onField('name', e.target.value)}
              required
              className={FIELD}
            />
          </div>

          <div>
            <label htmlFor="reg-manifest" className={FIELD_LABEL}>
              MANIFEST PATH / URL
            </label>
            <input
              id="reg-manifest"
              type="text"
              placeholder="e.g. packages/windows-triage-mcp/sift-backend.json or http://…"
              value={manifestPath}
              onChange={(e) => onField('manifestPath', e.target.value)}
              className={FIELD}
            />
          </div>

          {type === 'stdio' ? (
            <>
              <div>
                <label htmlFor="reg-command" className={FIELD_LABEL}>
                  COMMAND *
                </label>
                <input
                  id="reg-command"
                  type="text"
                  placeholder="e.g. node or python"
                  value={command}
                  onChange={(e) => onField('command', e.target.value)}
                  required
                  className={FIELD}
                />
              </div>

              <div>
                <label htmlFor="reg-args" className={FIELD_LABEL}>
                  ARGUMENTS (One per line or JSON Array)
                </label>
                <textarea
                  id="reg-args"
                  placeholder={'e.g.\n--verbose\n--port\n8080\nor ["--verbose", "--port", "8080"]'}
                  value={argsStr}
                  onChange={(e) => onField('argsStr', e.target.value)}
                  rows={3}
                  className={cn(FIELD, 'mono resize-none')}
                />
              </div>

              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className={cn(FIELD_LABEL, 'mb-0')}>ENV VAR REFERENCES</label>
                  <button
                    type="button"
                    onClick={envActions.add}
                    className="mono flex items-center gap-1 text-[10px] font-semibold text-primary hover:underline"
                  >
                    <Plus className="size-3" aria-hidden /> Add Row
                  </button>
                </div>
                <div className="max-h-[160px] space-y-2 overflow-y-auto pr-1">
                  {envList.map((row, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Backend env"
                        value={row.key}
                        onChange={(e) => envActions.update(index, 'key', e.target.value)}
                        className={cn(FIELD, 'w-1/2 px-2 py-1')}
                      />
                      <input
                        type="text"
                        placeholder="Gateway env var"
                        value={row.value}
                        onChange={(e) => envActions.update(index, 'value', e.target.value)}
                        className={cn(FIELD, 'w-1/2 px-2 py-1')}
                      />
                      <button
                        type="button"
                        onClick={() => envActions.remove(index)}
                        aria-label="Remove env row"
                        className="px-1 text-muted-foreground transition-colors hover:text-destructive"
                      >
                        <X className="size-3.5" aria-hidden />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <>
              <div>
                <label htmlFor="reg-url" className={FIELD_LABEL}>
                  URL *
                </label>
                <input
                  id="reg-url"
                  type="url"
                  placeholder="e.g. http://localhost:8080/mcp"
                  value={url}
                  onChange={(e) => onField('url', e.target.value)}
                  required
                  className={FIELD}
                />
              </div>

              <div>
                <label htmlFor="reg-bearer" className={FIELD_LABEL}>
                  BEARER TOKEN ENV VAR
                </label>
                <input
                  id="reg-bearer"
                  type="text"
                  placeholder="SIFT_BACKEND_NAME_TOKEN"
                  value={bearerTokenEnv}
                  onChange={(e) => onField('bearerTokenEnv', e.target.value)}
                  className={FIELD}
                />
              </div>

              <div>
                <label htmlFor="reg-tls" className={FIELD_LABEL}>
                  TLS CERT PATH ENV VAR
                </label>
                <input
                  id="reg-tls"
                  type="text"
                  placeholder="SIFT_BACKEND_NAME_TLS_CERT"
                  value={tlsCertEnv}
                  onChange={(e) => onField('tlsCertEnv', e.target.value)}
                  className={FIELD}
                />
              </div>
            </>
          )}

          <div className="grid grid-cols-2 gap-3 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onValidate}
              disabled={validating}
              className="text-xs font-semibold"
            >
              {validating && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
              Validate
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={onRegister}
              className="text-xs font-semibold"
            >
              Register
            </Button>
          </div>
        </form>
      </div>

      <ValidationResult result={validationResult} />
    </div>
  )
}
