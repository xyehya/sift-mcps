import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { tabLabel } from '@/lib/nav'

// ─────────────────────────────────────────────────────────────────────────
// Placeholder panel rendered for tabs whose real content is built in a later
// phase (Overview + Findings = RUN-3; the rest = Phase 1 feature agents). It
// gives every destination a consistent, on-brand skeleton so the shell — nav,
// routing, auth gating, theming — is demoable end-to-end without feature work.
// ─────────────────────────────────────────────────────────────────────────

export function TabPlaceholder({ tabId }) {
  const label = tabLabel(tabId)
  return (
    <section aria-label={`${label} (coming soon)`} className="mx-auto flex w-full max-w-6xl flex-col gap-6 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">{label}</h1>
        <p className="text-sm text-muted-foreground">
          This panel is part of the v3 rebuild and will be wired up shortly.
        </p>
      </div>

      {/* KPI skeleton row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <Skeleton className="h-3 w-20" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-7 w-12" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Content skeleton */}
      <Card>
        <CardHeader>
          <Skeleton className="h-4 w-40" />
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <Skeleton className="size-8 rounded-full" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-16" />
            </div>
          ))}
        </CardContent>
      </Card>
    </section>
  )
}
