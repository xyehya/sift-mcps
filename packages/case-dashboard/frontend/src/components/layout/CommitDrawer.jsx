import { useMemo, useRef, useState } from 'react'
import { Check, Lock, Pencil, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { deleteDelta, postCommit } from '@/api/endpoints'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'

// ─────────────────────────────────────────────────────────────────────────
// Commit Drawer (spec §4) — review staged delta, then commit. Security
// contract preserved (SessionChanges "no password bypass"): commit requires a
// manually-typed examiner password AND a deliberate 3-second hold; the palette
// only opens this drawer, it never auto-commits. Password is cleared from
// state the instant it is submitted to the server (CL3a Supabase re-verify).
// ─────────────────────────────────────────────────────────────────────────

const HOLD_MS = 3000

const ACTION_META = {
  approve: { icon: Check, cls: 'text-status-approved border-status-approved/40' },
  reject: { icon: X, cls: 'text-destructive border-destructive/40' },
  edit: { icon: Pencil, cls: 'text-status-pending border-status-pending/40' },
}

export function CommitDrawer() {
  const { open, setOpen, delta, setDelta, findings, addToast } = useStoreSlice((s) => ({
    open: s.commitDrawerOpen,
    setOpen: s.setCommitDrawerOpen,
    delta: s.delta,
    setDelta: s.setDelta,
    findings: s.findings,
    addToast: s.addToast,
  }))

  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [success, setSuccess] = useState(false)
  const [holdPct, setHoldPct] = useState(0)
  const holdTimer = useRef(null)
  const holdRAF = useRef(null)

  const findingById = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings])
  const canCommit = delta.length > 0 && password.length > 0

  async function removeItem(id) {
    try {
      await deleteDelta(id)
      setDelta(delta.filter((d) => d.id !== id))
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  function stopHold() {
    if (holdTimer.current) clearTimeout(holdTimer.current)
    if (holdRAF.current) clearInterval(holdRAF.current)
    holdTimer.current = null
    holdRAF.current = null
    setHoldPct(0)
  }

  function startHold() {
    if (!canCommit) return
    // Drive progress off the tick count rather than a wall-clock read so the
    // handler body stays free of impure calls (react-hooks/purity).
    const TICK_MS = 50
    let elapsed = 0
    holdRAF.current = setInterval(() => {
      elapsed += TICK_MS
      setHoldPct(Math.min(100, (elapsed / HOLD_MS) * 100))
    }, TICK_MS)
    holdTimer.current = setTimeout(() => {
      stopHold()
      doCommit()
    }, HOLD_MS)
  }

  async function doCommit() {
    setErr('')
    try {
      // CL3a (B-MVP-017): password re-verified server-side against Supabase
      // over TLS — no local HMAC round-trip. Clear it from state immediately.
      const submitted = password
      setPassword('')
      await postCommit({ password: submitted })
      setDelta([])
      setSuccess(true)
      addToast('Changes committed successfully', 'success')
      setTimeout(() => {
        setSuccess(false)
        setOpen(false)
      }, 2200)
    } catch (ex) {
      console.error('Commit failed:', ex)
      setErr('Commit failed — check your password and try again.')
    }
  }

  function handleOpenChange(next) {
    if (!next) {
      stopHold()
      setErr('')
    }
    setOpen(next)
  }

  return (
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetContent side="right" className="w-full gap-0 p-0 sm:max-w-md">
        <SheetHeader className="border-b border-border">
          <SheetTitle>Commit staged changes</SheetTitle>
          <SheetDescription>
            Review the staged review actions, then hold to commit. Cryptographically signed.
          </SheetDescription>
        </SheetHeader>

        {success ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-6 text-center">
            <span className="flex size-14 items-center justify-center rounded-full bg-status-approved/15 text-status-approved">
              <Lock className="size-6" />
            </span>
            <p className="text-lg font-semibold text-status-approved">Committed</p>
            <p className="mono text-xs text-muted-foreground">Evidence chain updated</p>
          </div>
        ) : (
          <>
            <div className="flex-1 space-y-2 overflow-y-auto p-4">
              {delta.length === 0 ? (
                <p className="mono text-xs text-muted-foreground">No staged changes.</p>
              ) : (
                delta.map((d) => {
                  const meta = ACTION_META[d.action] ?? ACTION_META.edit
                  const Icon = meta.icon
                  const f = findingById.get(d.id)
                  return (
                    <div
                      key={d.id}
                      className={cn('flex items-center gap-2 rounded-md border border-dashed px-2.5 py-2 text-xs', meta.cls)}
                    >
                      <Icon className="size-3.5 shrink-0" aria-hidden />
                      <span className="mono shrink-0 text-muted-foreground">{d.id}</span>
                      <span className="flex-1 truncate text-foreground">{f?.title ?? d.id}</span>
                      <button
                        type="button"
                        onClick={() => removeItem(d.id)}
                        aria-label={`Unstage ${d.id}`}
                        className="shrink-0 text-muted-foreground transition-colors hover:text-destructive"
                      >
                        <X className="size-3.5" />
                      </button>
                    </div>
                  )
                })
              )}
            </div>

            <div className="space-y-3 border-t border-border p-4">
              {err && (
                <p role="alert" aria-live="assertive" className="text-sm text-destructive">
                  {err}
                </p>
              )}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="commit-password">Examiner password</Label>
                <Input
                  id="commit-password"
                  type="password"
                  autoComplete="current-password"
                  className="mono"
                  value={password}
                  disabled={delta.length === 0}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              <button
                type="button"
                disabled={!canCommit}
                onMouseDown={startHold}
                onMouseUp={stopHold}
                onMouseLeave={stopHold}
                onTouchStart={startHold}
                onTouchEnd={stopHold}
                onTouchCancel={stopHold}
                onBlur={stopHold}
                className={cn(
                  'relative w-full select-none overflow-hidden rounded-md border border-primary bg-primary/15 py-2.5 text-sm font-semibold text-primary transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  'disabled:cursor-not-allowed disabled:opacity-40',
                )}
              >
                <span className="relative z-10">
                  {holdPct > 0 ? `Hold to confirm… ${Math.round(holdPct)}%` : 'Hold to commit'}
                </span>
              </button>
              {holdPct > 0 && <Progress value={holdPct} className="h-1" />}
              <p className="mono text-center text-[10px] text-muted-foreground">
                Hold for 3 seconds to confirm. This action is cryptographically signed.
              </p>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
