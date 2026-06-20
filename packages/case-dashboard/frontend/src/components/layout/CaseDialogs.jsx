import { useState } from 'react'

import { useStoreSlice } from '@/store/useStore'
import {
  getCaseActivateChallenge,
  postCaseActivate,
  postCaseCreate,
} from '@/api/endpoints'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

// ─────────────────────────────────────────────────────────────────────────
// Case activation + creation dialogs (behavior-preserving port of old
// Header.jsx, spec §6). Two contract details are preserved exactly:
//   • Activate challenge: getCaseActivateChallenge() → {required:false} means
//     DB/Supabase authority (the session itself gates activation, no per-action
//     password). Otherwise (file-backed, CL3a/B-MVP-017) the operator password
//     is re-verified server-side against Supabase.
//   • On success, every case-scoped store slice is reset and isLoading flipped
//     so the next 15s poll repopulates against the newly active case.
// ─────────────────────────────────────────────────────────────────────────

/** Reset all case-scoped data after an activate/create; next poll repopulates. */
function useResetCaseScope() {
  const reset = useStoreSlice((s) => ({
    setFindings: s.setFindings,
    setTimeline: s.setTimeline,
    setDelta: s.setDelta,
    setChainStatus: s.setChainStatus,
    setIocs: s.setIocs,
    setTodos: s.setTodos,
    setReports: s.setReports,
    setSummary: s.setSummary,
    setActiveCase: s.setActiveCase,
    setIsLoading: s.setIsLoading,
  }))
  return () => {
    reset.setFindings([])
    reset.setTimeline([])
    reset.setDelta([])
    reset.setChainStatus(null)
    reset.setIocs([])
    reset.setTodos([])
    reset.setReports([])
    reset.setSummary(null)
    reset.setActiveCase(null)
    reset.setIsLoading(true)
  }
}

export function ActivateCaseDialog({ activatingCase, onClose }) {
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const resetCaseScope = useResetCaseScope()
  const open = Boolean(activatingCase)

  async function confirm(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const challenge = await getCaseActivateChallenge()
      // DB authority mode → {required:false}: no per-action re-auth. File-backed
      // branch re-verifies the operator password server-side against Supabase.
      const dbAuthority = challenge?.required === false
      const payload = { case_id: activatingCase.id }
      if (!dbAuthority) payload.password = password
      setPassword('')
      await postCaseActivate(payload)
      resetCaseScope()
      setBusy(false)
      onClose()
    } catch (ex) {
      console.error('Activation failed:', ex)
      setBusy(false)
      setErr('Activation failed. Verify password and try again.')
    }
  }

  function handleOpenChange(next) {
    if (!next && !busy) {
      setPassword('')
      setErr('')
      onClose()
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={confirm} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>
              Activate case <span className="mono text-primary">{activatingCase?.id}</span>
            </DialogTitle>
            <DialogDescription>
              Re-authentication is verified against Supabase. The DB-authority deployment may not
              require a password.
            </DialogDescription>
          </DialogHeader>
          {err && (
            <p role="alert" aria-live="assertive" className="text-sm text-destructive">
              {err}
            </p>
          )}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="activate-password">Password</Label>
            <Input
              id="activate-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? 'Activating…' : 'Activate'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function CreateCaseDialog({ open, onOpenChange }) {
  const [name, setName] = useState('')
  const [title, setTitle] = useState('')
  const [synopsis, setSynopsis] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const resetCaseScope = useResetCaseScope()

  function resetForm() {
    setName('')
    setTitle('')
    setSynopsis('')
    setErr('')
  }

  async function confirm(e) {
    e.preventDefault()
    setErr('')
    const casename = name.trim().toLowerCase()
    const caseTitle = title.trim()
    if (!casename || !caseTitle) {
      setErr('Case name and title are required.')
      return
    }
    setBusy(true)
    try {
      const desc = synopsis.trim()
      // Backend computes case_id + directory and auto-activates the new case.
      await postCaseCreate(desc ? { casename, title: caseTitle, description: desc } : { casename, title: caseTitle })
      resetCaseScope()
      setBusy(false)
      resetForm()
      onOpenChange(false)
    } catch (ex) {
      console.error('Case creation failed:', ex)
      setBusy(false)
      let msg = 'Case creation failed. Check your role and try again.'
      if (ex?.message) {
        try {
          msg = JSON.parse(ex.message).error || msg
        } catch {
          msg = ex.message
        }
      }
      setErr(msg)
    }
  }

  function handleOpenChange(next) {
    if (busy) return
    if (!next) resetForm()
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={confirm} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>Create new case</DialogTitle>
            <DialogDescription>The new case is created and activated immediately.</DialogDescription>
          </DialogHeader>
          {err && (
            <p role="alert" aria-live="assertive" className="text-sm text-destructive">
              {err}
            </p>
          )}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="case-name">Case name</Label>
            <Input
              id="case-name"
              className="mono"
              placeholder="e.g. rocba"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
            <p className="text-xs text-muted-foreground">Lowercase — used to derive the case id.</p>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="case-title">Title</Label>
            <Input
              id="case-title"
              placeholder="e.g. ROCBA intrusion investigation"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="case-synopsis">Synopsis (optional)</Label>
            <Textarea
              id="case-synopsis"
              rows={4}
              placeholder="Short narrative: what happened, the in-scope system(s), and the investigative objectives."
              value={synopsis}
              onChange={(e) => setSynopsis(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? 'Creating…' : 'Create case'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
