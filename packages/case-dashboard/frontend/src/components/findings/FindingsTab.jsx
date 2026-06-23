import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { CheckCheck, ListChecks } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { parseHashFilters } from '@/hooks/useHashRoute'
import { useDeltaRefetch } from '@/hooks/useDeltaRefetch'
import { postDelta, deleteDelta } from '@/api/endpoints'
import {
  buildEditItem,
  buildStageItem,
  filterFindings,
  reviewCounts,
  upsertDelta,
} from '@/components/findings/findings-utils'
import { FindingsList } from '@/components/findings/FindingsList'
import { FindingDetail } from '@/components/findings/FindingDetail'
import { MasterDetailLayout } from '@/components/common/MasterDetailLayout'

// ─────────────────────────────────────────────────────────────────────────
// Findings (handoff Screen 2) — full-height flex column: header + stat cards
// + two-pane grid (5fr list / 7fr detail). List uses a unified filter-dropdown
// (replaces the old tab-strip). Detail shows the three handoff fields only
// (Observation·fact · Interpretation·analysis · Justification & custody).
// Keyboard review (j/k/a/s/r). Store/api/hooks public paths unchanged.
//
// F2 (operator decision, 2026-06-22): Approve is IMMEDIATE — it stages a
// reversible `approve` delta via postDelta, exactly like Stage/Reject. The old
// step-up password modal was dropped. This deviates from the settled handoff's
// "step-up on Approve", but the real irreversible gate (Commit-to-record) is
// already server-re-authed (CommitDrawer → postCommit({password}) → Supabase),
// so a password on the reversible Approve was friction-theater + inconsistent
// with Stage/Reject.
// ─────────────────────────────────────────────────────────────────────────

function EmptyDetail() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <ListChecks className="size-8 opacity-40" aria-hidden />
      <p className="mono text-sm">Select a finding to review</p>
    </div>
  )
}

/** Header "Commit to record" button — glass chip, orange text, staged-count badge.
 *  Gradient surface / edge highlight / orange-mixed border are literal token-var
 *  arbitrary classes (no hex, no inline color). */
function CommitButton({ stagedCount, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 rounded-[9px] border border-[color-mix(in_srgb,var(--orange)_38%,var(--border-hard))] bg-[linear-gradient(155deg,var(--bg-raised),var(--bg-surface))] px-3.5 py-1.5 text-sm font-semibold text-orange shadow-[var(--edge)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <CheckCheck className="size-4 shrink-0" aria-hidden />
      Commit to record
      <span className="mono rounded-md bg-orange/16 px-1.5 py-px text-[11px] font-semibold">
        {stagedCount}
      </span>
    </button>
  )
}

/** 4 symmetric stat cards — Findings / Approved / Pending / Staged.
 *  Per-card numeral color + wash are literal token classes (CONF_CLASS pattern). */
const STAT_CARDS = [
  { key: 'total',    label: 'Findings', num: 'text-text-bright', wash: '' },
  { key: 'approved', label: 'Approved', num: 'text-jade',        wash: 'bg-jade/8' },
  { key: 'pending',  label: 'Pending',  num: 'text-amber',       wash: 'bg-amber/8' },
  { key: 'staged',   label: 'Staged',   num: 'text-violet',      wash: 'bg-violet/8' },
]

function StatCards({ counts }) {
  return (
    <div className="grid shrink-0 grid-cols-4 gap-3">
      {STAT_CARDS.map((c) => (
        <div
          key={c.label}
          className={cn('rounded-[12px] border border-border-soft p-3 shadow-[var(--edge)]', c.wash)}
        >
          <div className={cn('font-display text-[22px] font-bold leading-none', c.num)}>
            {counts[c.key] ?? 0}
          </div>
          <div className="mono mt-1.5 text-[9px] uppercase tracking-[.12em] text-text-muted">
            {c.label}
          </div>
        </div>
      ))}
    </div>
  )
}

export function FindingsTab() {
  const {
    findings, delta, setDelta, selectedFindingId, setSelectedFindingId, timeline,
    addToast, isLoading, findingsFilter, findingsHostFilter, findingsAccountFilter,
    setActiveTab, commandPaletteOpen, user, setCommitDrawerOpen,
  } = useStoreSlice((s) => ({
    findings: s.findings,
    delta: s.delta,
    setDelta: s.setDelta,
    selectedFindingId: s.selectedFindingId,
    setSelectedFindingId: s.setSelectedFindingId,
    timeline: s.timeline,
    addToast: s.addToast,
    isLoading: s.isLoading,
    findingsFilter: s.findingsFilter,
    findingsHostFilter: s.findingsHostFilter,
    findingsAccountFilter: s.findingsAccountFilter,
    setActiveTab: s.setActiveTab,
    commandPaletteOpen: s.commandPaletteOpen,
    user: s.user,
    setCommitDrawerOpen: s.setCommitDrawerOpen,
  }))

  const refetchDelta = useDeltaRefetch()
  const canReview = (user?.role || '').toLowerCase() === 'examiner'
  const [search, setSearch] = useState('')
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState(() => new Set())

  // Severity filter rides the hash (`#/findings?sev=high`) — kept in sync on
  // back/forward (RUN-4c deep-link plumbing).
  const [severityFilter, setSeverityFilter] = useState(() => parseHashFilters(window.location.hash).sev ?? null)
  useEffect(() => {
    const sync = () => setSeverityFilter(parseHashFilters(window.location.hash).sev ?? null)
    window.addEventListener('hashchange', sync)
    return () => window.removeEventListener('hashchange', sync)
  }, [])
  const clearSeverity = useCallback(() => {
    setSeverityFilter(null)
    window.history.replaceState(null, '', '#/findings')
  }, [])

  const findingById = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings])
  const deltaById = useMemo(() => new Map((delta ?? []).map((d) => [d.id, d])), [delta])
  const filtered = useMemo(
    () => filterFindings(findings, { filter: findingsFilter, host: findingsHostFilter, account: findingsAccountFilter, confidence: severityFilter, search }),
    [findings, findingsFilter, findingsHostFilter, findingsAccountFilter, severityFilter, search],
  )
  const counts = useMemo(() => {
    const base = reviewCounts(findings)
    const approved = findings.filter((f) => (f.status ?? '').toLowerCase() === 'approved').length
    const staged = (delta ?? []).filter((d) => d.action === 'stage').length
    return { ...base, total: findings.length, approved, staged }
  }, [findings, delta])

  const stagedCount = (delta ?? []).length

  const currentFinding = selectedFindingId ? findingById.get(selectedFindingId) ?? null : null
  const stagedItem = currentFinding ? deltaById.get(currentFinding.id) ?? null : null

  // ---- delta mutations (POST replaces the whole delta document) ----
  const stage = useCallback(
    async (findingId, action) => {
      const f = findingById.get(findingId)
      if (!f) return
      const next = upsertDelta(delta, buildStageItem(f, action))
      const VERB = { approve: 'Approved', reject: 'Rejected', stage: 'Staged' }
      const TONE = { approve: 'success', reject: 'warn', stage: 'info' }
      try {
        await postDelta({ items: next })
        setDelta(next)
        addToast(`${VERB[action] ?? 'Staged'} ${findingId} — staged for commit`, TONE[action] ?? 'info')
        refetchDelta() // B2: reconcile badge with server truth without waiting for the 15s poll
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [findingById, delta, setDelta, addToast, refetchDelta],
  )

  const unstage = useCallback(
    async (findingId) => {
      try {
        await deleteDelta(findingId)
        setDelta(delta.filter((d) => d.id !== findingId))
        addToast(`Unstaged ${findingId}`, 'info')
        refetchDelta() // B2: reconcile badge with server truth without waiting for the 15s poll
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [delta, setDelta, addToast, refetchDelta],
  )

  const editField = useCallback(
    async (finding, field, original, modified) => {
      const next = upsertDelta(delta, buildEditItem(deltaById.get(finding.id), finding, field, original, modified))
      try {
        await postDelta({ items: next })
        setDelta(next)
        addToast(`Updated ${field} (staged)`, 'success')
        refetchDelta() // B2: reconcile badge with server truth without waiting for the 15s poll
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [delta, deltaById, setDelta, addToast, refetchDelta],
  )

  async function batch(action) {
    for (const id of selectedIds) await stage(id, action)
    setSelectedIds(new Set())
    setSelectMode(false)
  }

  function toggleSelectId(id) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // ---- keyboard review (j/k navigate · a approve · s stage · r reject) ----
  const filteredRef = useRef(filtered)
  const selectedRef = useRef(selectedFindingId)
  const stageRef = useRef(stage)
  useEffect(() => { filteredRef.current = filtered }, [filtered])
  useEffect(() => { selectedRef.current = selectedFindingId }, [selectedFindingId])
  useEffect(() => { stageRef.current = stage }, [stage])

  useEffect(() => {
    function onKey(e) {
      const tag = document.activeElement?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || document.activeElement?.isContentEditable) return
      if (commandPaletteOpen) return
      const list = filteredRef.current
      const curId = selectedRef.current
      const idx = list.findIndex((f) => f.id === curId)
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault()
        const nextF = idx < 0 ? list[0] : list[idx + 1]
        if (nextF) setSelectedFindingId(nextF.id)
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault()
        if (idx > 0) setSelectedFindingId(list[idx - 1].id)
      } else if (canReview && e.key === 'a' && curId) {
        // F2: Approve is immediate (stages a reversible approve delta).
        e.preventDefault()
        stageRef.current(curId, 'approve')
      } else if (canReview && e.key === 's' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'stage')
      } else if (canReview && e.key === 'r' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'reject')
      } else if (e.key === 'Escape') {
        // Esc closes any open overlay — handled in child modals; nothing to do here
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [commandPaletteOpen, canReview, setSelectedFindingId])

  // Full-height flex column: header (shrink-0) + stat cards (shrink-0) + two-pane
  // MasterDetailLayout (flex-1). `h-full min-h-0` fits the viewport-bounded
  // <main> cell (AppShell) — no magic height, zoom-safe (SCR-2 / §8).
  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex shrink-0 items-start justify-between gap-4 px-5 pt-5 pb-4">
        <div>
          <h1 className="font-display text-[24px] font-bold leading-none tracking-[-.4px] text-text-bright">
            Findings review
          </h1>
          <p className="mono mt-1.5 text-xs text-text-muted">
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">j</kbd>
            <kbd className="mono ml-1 rounded border border-border bg-secondary px-1 py-px text-[10px]">k</kbd>
            {' '}move ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">a</kbd>
            {' '}approve ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">r</kbd>
            {' '}reject ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">s</kbd>
            {' '}stage
          </p>
        </div>
        <CommitButton stagedCount={stagedCount} onClick={() => setCommitDrawerOpen(true)} />
      </div>

      {/* ── Stat cards ──────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 pb-4">
        <StatCards counts={counts} />
      </div>

      {/* ── Two-pane master-detail (5fr list / 7fr detail) ──────────────
          Both panes own their internal scroll (FindingsList / FindingDetail
          roots are overflow-hidden with inner overflow-y-auto), so the layout
          supplies only the bounded min-h-0 box (scroll={false}) — single
          scrollbar per pane, no double scroll owner. */}
      <MasterDetailLayout
        className="flex-1"
        ariaLabel="Findings review"
        listScroll={false}
        detailScroll={false}
        list={
          <FindingsList
            list={filtered}
            loading={isLoading}
            counts={counts}
            canReview={canReview}
            search={search}
            onSearch={setSearch}
            severityFilter={severityFilter}
            onClearSeverity={clearSeverity}
            selectMode={selectMode}
            onToggleSelectMode={() => {
              setSelectMode((v) => !v)
              setSelectedIds(new Set())
            }}
            selectedIds={selectedIds}
            onToggleSelectId={toggleSelectId}
            onBatch={batch}
          />
        }
        detail={
          currentFinding ? (
            <FindingDetail
              key={currentFinding.id}
              finding={currentFinding}
              stagedItem={stagedItem}
              timeline={timeline}
              canReview={canReview}
              addToast={addToast}
              onApprove={() => stage(currentFinding.id, 'approve')}
              onStage={() => stage(currentFinding.id, 'stage')}
              onReject={() => stage(currentFinding.id, 'reject')}
              onUnstage={stagedItem ? () => unstage(currentFinding.id) : null}
              onEdit={(field, original, modified) => editField(currentFinding, field, original, modified)}
              onNavigate={(fid) => {
                setSelectedFindingId(fid)
                setActiveTab('findings')
              }}
            />
          ) : (
            <div className="flex h-full min-w-0 flex-col overflow-hidden">
              <EmptyDetail />
            </div>
          )
        }
      />
    </div>
  )
}
