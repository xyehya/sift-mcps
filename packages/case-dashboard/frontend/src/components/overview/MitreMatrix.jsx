import { mitreTechniques } from '@/components/overview/overview-metrics'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK matrix — distinct technique ids referenced across findings,
// rendered as token-styled chips with a tooltip hint. No external navigation
// (CSP stays 'self'); chips are informational. Empty state guides the examiner.
// ─────────────────────────────────────────────────────────────────────────

export function MitreMatrix({ findings }) {
  const ids = mitreTechniques(findings)

  if (ids.length === 0) {
    return <p className="text-sm text-muted-foreground">No MITRE ATT&CK techniques mapped in findings yet.</p>
  }

  return (
    <div className="flex flex-wrap gap-1.5" aria-label={`${ids.length} MITRE ATT&CK techniques`}>
      {ids.map((id) => (
        <Tooltip key={id}>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="mono cursor-default text-[11px]">
              {id}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>MITRE ATT&CK technique {id}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  )
}
