import { useRef, useState } from 'react'
import { Check, KeyRound } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'

// ─────────────────────────────────────────────────────────────────────────
// StepUpApproveModal — password-gated approval dialog (handoff model-shift §3).
// The "Authorize & approve" button is disabled until a non-empty password is
// entered. Prototype accepts any non-empty password; production wires to real
// step-up auth.
// ─────────────────────────────────────────────────────────────────────────

export function StepUpApproveModal({ findingId, open, onClose, onConfirm }) {
  const [pass, setPass] = useState('')
  const inputRef = useRef(null)

  const handleOpenChange = (next) => {
    if (!next) { setPass(''); onClose() }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="max-w-sm"
        onOpenAutoFocus={(e) => { e.preventDefault(); inputRef.current?.focus() }}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
            <KeyRound className="size-4 text-status-approved" aria-hidden />
            Step-up authorization · Approve {findingId}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-xs">
          <p className="leading-relaxed text-muted-foreground">
            Approving a finding is a chain-of-custody action. Enter your examiner password to authorize.
          </p>
          <div className="space-y-1.5">
            {/* text-xs — meets WCAG resize requirement for form labels */}
            <label htmlFor="stepup-pass" className="mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Examiner password
            </label>
            <Input
              ref={inputRef}
              id="stepup-pass"
              type="password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && pass) onConfirm(pass) }}
              placeholder="Enter password…"
              autoComplete="current-password"
              className="h-9 text-sm"
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" size="sm" onClick={() => { setPass(''); onClose() }}>
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={!pass}
            onClick={() => {
              // TODO(CG-AUTH): wire onConfirm(pass) → computeChallengeResponse() → POST /api/auth/step-up-approve (see EvidenceUnseal)
              onConfirm(pass)
            }}
            className="gap-1.5 bg-status-approved text-primary-foreground hover:bg-status-approved/90 disabled:opacity-50"
          >
            <Check className="size-3.5" aria-hidden />
            Authorize &amp; approve
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
