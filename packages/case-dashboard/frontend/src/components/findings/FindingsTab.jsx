import { useState, useMemo, useEffect, useRef } from 'react'
import { useStore } from '../../store/useStore'
import { postDelta, deleteDelta, getAudit } from '../../api/endpoints'
import { formatDistanceToNow } from 'date-fns'
import { Skeleton } from '../common/Skeleton'
import clsx from 'clsx'

const CONF_COLOR = {
  HIGH:        'var(--crimson)',
  MEDIUM:      'var(--amber)',
  LOW:         'var(--cyan)',
  SPECULATIVE: 'var(--violet)',
}

const CONF_SHAPE = { HIGH: '▲', MEDIUM: '◆', LOW: '●', SPECULATIVE: '◇' }

const CONF_DIM = {
  HIGH:        'var(--crimson-dim)',
  MEDIUM:      'var(--amber-dim)',
  LOW:         'var(--cyan-dim)',
  SPECULATIVE: 'var(--violet-dim)',
}
const PROV_ICON = { MCP: '●', HOOK: '○', SHELL: '▲', MIXED: '◑', NONE: '✕' }

export function getTagString(t) {
  if (typeof t === 'object' && t !== null) {
    return t.value ?? JSON.stringify(t)
  }
  return String(t)
}

export function FindingsTab() {
  const { findings, delta, setDelta, selectedFindingId, setSelectedFindingId, timeline, addToast, isLoading, findingsFilter, setFindingsFilter, findingsHostFilter, setFindingsHostFilter, findingsAccountFilter, setFindingsAccountFilter, commandPaletteOpen } = useStore()
  const filter = findingsFilter
  const setFilter = (f) => { setFindingsFilter(f); setSelectedFindingId(null) }
  const [search, setSearch] = useState('')
  const [selectMode, setSelectMode] = useState(false)
  const [selected, setSelected] = useState(new Set())

  const filtered = useMemo(() => {
    let list = findings
    const st = (f) => (f.status ?? '').toLowerCase()
    if (filter === 'pending')  list = list.filter((f) => st(f) === 'draft')
    if (filter === 'approved') list = list.filter((f) => st(f) === 'approved')
    if (filter === 'rejected') list = list.filter((f) => st(f) === 'rejected')
    if (findingsHostFilter) {
      console.log('Filtering findings by host:', findingsHostFilter)
      list = list.filter((f) => {
        const match = (f.host ?? '').toUpperCase() === findingsHostFilter.toUpperCase()
        console.log(`Finding ${f.id} host: "${f.host}" match:`, match)
        return match
      })
    }
    if (findingsAccountFilter !== null) {
      if (findingsAccountFilter === '') {
        // N/A filter: findings with no affected_account
        list = list.filter((f) => {
          const raw = f.affected_account || f.account
          return !raw || (typeof raw === 'string' && raw.trim() === '') || (Array.isArray(raw) && raw.length === 0)
        })
      } else {
        list = list.filter((f) => {
          const raw = f.affected_account || f.account
          if (!raw) return false
          if (Array.isArray(raw)) return raw.some(a => (typeof a === 'string' ? a : a?.value ?? '') === findingsAccountFilter)
          if (typeof raw === 'string') return raw.split(',').map(s => s.trim()).includes(findingsAccountFilter)
          return false
        })
      }
    }
    if (search) {
      const q = search.toLowerCase()
      list = list.filter((f) => f.id.toLowerCase().includes(q) || (f.title ?? '').toLowerCase().includes(q))
    }
    return list
  }, [findings, filter, search, findingsHostFilter, findingsAccountFilter])

  const currentFinding = findings.find((f) => f.id === selectedFindingId) ?? null
  const stagedItem = currentFinding ? delta.find((d) => d.id === currentFinding.id) : null

  // POST /api/delta replaces the WHOLE delta file — always send all current items
  async function stageAction(findingId, action, note = '') {
    const finding = findings.find((f) => f.id === findingId)
    if (!finding) return
    const newItem = {
      id: findingId,
      type: finding.type ?? 'finding',
      action,
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
      ...(note ? { note } : {}),
    }
    const existing = delta.filter((d) => d.id !== findingId)
    const newDelta = [...existing, newItem]
    try {
      await postDelta({ items: newDelta })
      setDelta(newDelta)
      addToast(`${action === 'approve' ? 'Approved' : 'Rejected'} ${findingId} — staged`, action === 'approve' ? 'success' : 'warn')
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  // DELETE /api/delta/{id} where id is the finding's id (e.g. F-001)
  async function unstage(findingId) {
    try {
      await deleteDelta(findingId)
      setDelta(delta.filter((d) => d.id !== findingId))
      addToast(`Unstaged ${findingId}`, 'info')
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  async function batchAction(action) {
    for (const fid of selected) await stageAction(fid, action)
    setSelected(new Set())
    setSelectMode(false)
  }

  const loading = isLoading

  const filteredRef = useRef(filtered)
  const selectedRef = useRef(selectedFindingId)
  const stageRef = useRef(stageAction)
  useEffect(() => { filteredRef.current = filtered }, [filtered])
  useEffect(() => { selectedRef.current = selectedFindingId }, [selectedFindingId])
  useEffect(() => { stageRef.current = stageAction }, [stageAction])

  useEffect(() => {
    function handleKeyDown(e) {
      const tag = document.activeElement?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (document.activeElement?.isContentEditable) return
      if (commandPaletteOpen) return
      const list = filteredRef.current
      const curId = selectedRef.current
      const idx = list.findIndex((f) => f.id === curId)
      if (e.key === 'j') {
        e.preventDefault()
        const next = idx < 0 ? list[0] : list[idx + 1]
        if (next) setSelectedFindingId(next.id)
      } else if (e.key === 'k') {
        e.preventDefault()
        if (idx > 0) setSelectedFindingId(list[idx - 1].id)
      } else if (e.key === 'a' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'approve')
      } else if (e.key === 'r' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'reject')
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [commandPaletteOpen, setSelectedFindingId])

  return (
    <div className="flex h-full overflow-hidden" style={{ background: 'var(--bg-base)' }}>
      {/* Sidebar */}
      <div className="w-72 shrink-0 flex flex-col border-r overflow-hidden"
        style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-surface)' }}>
        {/* Search */}
        <div className="p-3 border-b" style={{ borderColor: 'var(--border-faint)' }}>
          <input
            value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings…"
            className="w-full px-3 py-1.5 rounded text-xs font-sans focus:outline-none transition-colors"
            style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
          />
        </div>

        {/* Filter tabs */}
        <div className="flex border-b" style={{ borderColor: 'var(--border-faint)' }}>
          {['pending', 'approved', 'rejected', 'all'].map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className="flex-1 py-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider transition-colors capitalize"
              style={{
                color: filter === f ? 'var(--cyan)' : 'var(--text-muted)',
                borderBottom: filter === f ? '2px solid var(--cyan)' : '2px solid transparent',
              }}>
              {f}
            </button>
          ))}
        </div>

        {findingsHostFilter && (
          <div className="px-3 py-1.5 border-b flex items-center justify-between text-[11px] font-mono"
            style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-raised)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Host: <strong style={{ color: 'var(--cyan)' }}>{findingsHostFilter}</strong></span>
            <button onClick={() => setFindingsHostFilter(null)} className="text-text-muted hover:text-crimson font-sans text-xs font-semibold px-1">✕</button>
          </div>
        )}

        {findingsAccountFilter !== null && (
          <div className="px-3 py-1.5 border-b flex items-center justify-between text-[11px] font-mono"
            style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-raised)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Account: <strong style={{ color: 'var(--violet)' }}>{findingsAccountFilter === '' ? 'N/A' : findingsAccountFilter}</strong></span>
            <button onClick={() => setFindingsAccountFilter(null)} className="text-text-muted hover:text-crimson font-sans text-xs font-semibold px-1">✕</button>
          </div>
        )}

        {/* Finding list */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="p-4 space-y-3">
              {[80, 65, 90, 55, 75].map((w, i) => (
                <Skeleton key={i} style={{ width: `${w}%`, height: 12 }} />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <p className="p-4 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
              No {filter === 'all' ? '' : filter} findings.
            </p>
          ) : (
            filtered.map((f) => {
              const color = CONF_COLOR[f.confidence] ?? 'var(--text-muted)'
              const staged = delta.find((d) => d.id === f.id)
              const isSelected = selectMode && selected.has(f.id)
              const isActive = f.id === (currentFinding?.id)
              return (
                <button key={f.id}
                  onClick={() => {
                    if (selectMode) {
                      setSelected((s) => { const n = new Set(s); n.has(f.id) ? n.delete(f.id) : n.add(f.id); return n })
                    } else {
                      setSelectedFindingId(f.id)
                    }
                  }}
                  className="w-full text-left px-3 py-2.5 flex items-start gap-2 transition-colors text-xs"
                  style={{
                    background: isActive ? 'var(--bg-raised)' : 'transparent',
                  }}>
                  {selectMode && (
                    <span className="mt-0.5 w-3 h-3 rounded border shrink-0 flex items-center justify-center text-[8px]"
                      style={{ borderColor: isSelected ? 'var(--cyan)' : 'var(--border-hard)', background: isSelected ? 'var(--cyan-dim)' : 'transparent' }}>
                      {isSelected && '✓'}
                    </span>
                  )}
                  <span className="w-1.5 h-1.5 rounded-full shrink-0 mt-1" style={{ background: color }} title={f.confidence ?? ''} />
                  <span className="font-mono shrink-0" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{f.id}</span>
                  <span className="flex-1 truncate font-sans" style={{ color: 'var(--text-primary)' }}>{f.title}</span>
                  {staged && (
                    <span className="font-mono text-[9px] shrink-0"
                      style={{ color: staged.action === 'approve' ? 'var(--jade)' : 'var(--crimson)' }}>
                      {staged.action === 'approve' ? '✓' : '✗'}
                    </span>
                  )}
                </button>
              )
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-2 border-t text-[11px] font-sans flex items-center justify-between"
          style={{ borderColor: 'var(--border-faint)', color: 'var(--text-muted)' }}>
          <span>{findings.filter((f) => (f.status ?? '').toLowerCase() === 'draft').length} pending · {findings.filter((f) => (f.status ?? '').toLowerCase() !== 'draft').length} reviewed</span>
          <button onClick={() => { setSelectMode(!selectMode); setSelected(new Set()) }}
            style={{ color: selectMode ? 'var(--cyan)' : 'var(--text-muted)' }}>
            {selectMode ? 'cancel' : '☐ select'}
          </button>
        </div>

        {/* Batch toolbar */}
        {selectMode && selected.size > 0 && (
          <div className="flex gap-2 p-2 border-t" style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-overlay)' }}>
            <button onClick={() => batchAction('approve')}
              className="flex-1 py-1 rounded text-xs font-sans font-semibold"
              style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>
              ✓ Approve {selected.size}
            </button>
            <button onClick={() => batchAction('reject')}
              className="flex-1 py-1 rounded text-xs font-sans font-semibold"
              style={{ background: 'var(--crimson-dim)', color: 'var(--crimson)', border: '1px solid var(--crimson)' }}>
              ✗ Reject {selected.size}
            </button>
          </div>
        )}
      </div>

      {/* Detail pane */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {currentFinding ? (
          <FindingDetail
            finding={currentFinding}
            stagedItem={stagedItem}
            timeline={timeline}
            onApprove={() => stageAction(currentFinding.id, 'approve')}
            onReject={() => stageAction(currentFinding.id, 'reject')}
            onUnstage={stagedItem ? () => unstage(currentFinding.id) : null}
          />
        ) : (
          <div className="flex items-center justify-center h-full" style={{ color: 'var(--text-muted)' }}>
            <p className="font-mono text-sm">Select a finding to review</p>
          </div>
        )}
      </div>
    </div>
  )
}

function FindingDetail({ finding, stagedItem, timeline, onApprove, onReject, onUnstage }) {
  const { delta, setDelta, findings, addToast, setSelectedFindingId, setActiveTab } = useStore()
  const confColor = CONF_COLOR[finding.confidence] ?? 'var(--text-muted)'
  const [showContext, setShowContext] = useState(false)
  const [zone2Open, setZone2Open] = useState(false)
  const [auditData, setAuditData] = useState([])
  const [loadingAudit, setLoadingAudit] = useState(false)

  // Edit states
  const [editingField, setEditingField] = useState(null)
  const [editVal, setEditVal] = useState('')
  const [editTags, setEditTags] = useState([])

  // Load audit data when Zone 2 opens
  useEffect(() => {
    if (zone2Open && finding.id) {
      setLoadingAudit(true)
      getAudit(finding.id)
        .then(data => {
          setAuditData(data || [])
          setLoadingAudit(false)
        })
        .catch(err => {
          console.error(err)
          setLoadingAudit(false)
        })
    }
  }, [finding.id, zone2Open])

  // Reset editing on finding change
  useEffect(() => {
    setEditingField(null)
  }, [finding.id])

  // Timeline context: events within ±2h of finding timestamp
  const contextEvents = useMemo(() => {
    if (!finding.timestamp && !finding.event_timestamp) return []
    const rawTs = finding.event_timestamp || finding.timestamp
    if (!rawTs || !timeline.length) return []
    const ts = new Date(rawTs).getTime()
    const TWO_H = 2 * 3600 * 1000
    return timeline.filter((e) => {
      const et = new Date(e.timestamp).getTime()
      return Math.abs(et - ts) <= TWO_H
    }).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  }, [finding.timestamp, finding.event_timestamp, timeline])

  // Compute effective values (base + delta modifications)
  const eff = useMemo(() => {
    const res = { ...finding }
    if (stagedItem?.modifications) {
      for (const [key, mod] of Object.entries(stagedItem.modifications)) {
        res[key] = mod.modified
      }
    }
    return res
  }, [finding, stagedItem])

  function startEdit(field, val) {
    setEditingField(field)
    if (field === 'mitre_ids' || field === 'iocs') {
      setEditTags(Array.isArray(val) ? val.map(getTagString) : [])
    } else {
      setEditVal(val ?? '')
    }
  }

  function cancelEdit() {
    setEditingField(null)
    setEditVal('')
    setEditTags([])
  }

  async function saveEdit(field) {
    const newValue = (field === 'mitre_ids' || field === 'iocs') ? editTags : editVal
    const original = finding[field]
    const norm = (val) => Array.isArray(val) ? JSON.stringify(val.map(getTagString).sort()) : String(val ?? '')
    if (norm(newValue) === norm(original)) {
      cancelEdit()
      return
    }

    const existing = delta.find((d) => d.id === finding.id) || {
      id: finding.id,
      type: finding.type ?? 'finding',
      action: 'edit',
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
    }

    const modifications = {
      ...(existing.modifications ?? {}),
      [field]: { original, modified: newValue }
    }

    const updatedItem = {
      ...existing,
      modifications
    }

    const newDelta = [...delta.filter((d) => d.id !== finding.id), updatedItem]
    try {
      await postDelta({ items: newDelta })
      setDelta(newDelta)
      addToast(`Updated ${field} (staged)`, 'success')
      cancelEdit()
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  function navigateToFinding(fid) {
    setSelectedFindingId(fid)
    setActiveTab('findings')
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        
        {/* Sticky Header Bar */}
        <div className="p-4 rounded sticky top-0 z-10 shadow-md"
          style={{ background: CONF_DIM[finding.confidence] ?? 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm shrink-0" style={{ color: 'var(--text-muted)' }}>{finding.id}</span>
            <div className="flex-1 min-w-0">
              {editingField === 'title' ? (
                <div className="flex gap-2 items-center w-full mt-1">
                  <input value={editVal} onChange={(e) => setEditVal(e.target.value)}
                    className="flex-1 px-2 py-1 rounded text-sm focus:outline-none"
                    style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
                  <button onClick={() => saveEdit('title')} className="px-2 py-1 rounded text-xs font-sans font-semibold"
                    style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>Save</button>
                  <button onClick={cancelEdit} className="px-2 py-1 rounded text-xs font-sans"
                    style={{ color: 'var(--text-muted)' }}>Cancel</button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <h2 className="font-display font-bold text-base truncate" style={{ color: 'var(--text-bright)' }}>{eff.title}</h2>
                  <button onClick={() => startEdit('title', eff.title)} className="text-text-muted hover:text-cyan text-xs p-1" title="Edit title">✎</button>
                </div>
              )}
            </div>
          </div>
          
          <div className="flex flex-wrap gap-2 mt-2.5 items-center text-xs">
            <Badge color={confColor}>{CONF_SHAPE[eff.confidence]} {eff.confidence}</Badge>
            <Badge color="var(--text-bright)" subtle>{finding.type}</Badge>
            
            {/* Status Badge */}
            {stagedItem ? (
              <Badge color="var(--amber)">
                {stagedItem.action === 'approve' ? '✓ STAGED APPROVE' : stagedItem.action === 'reject' ? '✗ STAGED REJECT' : '✎ STAGED EDITS'}
              </Badge>
            ) : (
              <Badge color={finding.status?.toLowerCase() === 'approved' ? 'var(--jade)' : finding.status?.toLowerCase() === 'rejected' ? 'var(--crimson)' : 'var(--status-pending)'}>
                {finding.status?.toLowerCase() === 'approved' ? '✓ APPROVED' : finding.status?.toLowerCase() === 'rejected' ? '✗ REJECTED' : 'DRAFT'}
              </Badge>
            )}

            {/* Provenance Grade */}
            {finding.provenance_grade && (
              <div className="relative group inline-flex items-center gap-1">
                <span className="px-1.5 py-0.5 rounded font-mono text-[10px] tracking-wider uppercase border"
                  style={{
                    color: eff.provenance_grade === 'FULL' ? 'var(--grade-full)' : eff.provenance_grade === 'PARTIAL' ? 'var(--grade-partial)' : 'var(--grade-none)',
                    borderColor: eff.provenance_grade === 'FULL' ? 'var(--grade-full)44' : eff.provenance_grade === 'PARTIAL' ? 'var(--grade-partial)44' : 'var(--grade-none)44',
                    background: 'transparent'
                  }}>
                  Grade: {eff.provenance_grade}
                </span>
                <span className="cursor-help" title="Grade indicates evidence provenance: FULL (fully verified MCP logs), PARTIAL (partially verified), or UNGRADED (manual/unverified findings).">
                  <svg className="h-3.5 w-3.5 text-text-muted hover:text-text-primary transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
                  </svg>
                </span>
              </div>
            )}

            {/* Event Timestamp and Host Context */}
            {eff.host && (
              <span style={{ color: 'var(--text-muted)' }}>Host: <strong style={{ color: 'var(--text-primary)' }}>{eff.host}</strong></span>
            )}
            {(eff.event_timestamp || eff.timestamp) && (
              <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                {new Date(eff.event_timestamp || eff.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
              </span>
            )}
          </div>
        </div>

        {/* Staged Indicator */}
        {stagedItem && (
          <div className="px-3 py-2 rounded text-xs font-mono flex items-center justify-between"
            style={{
              borderStyle: 'dashed',
              borderWidth: 1,
              borderColor: stagedItem.action === 'approve' ? 'var(--jade)' : stagedItem.action === 'reject' ? 'var(--crimson)' : 'var(--amber)',
              color: stagedItem.action === 'approve' ? 'var(--jade)' : stagedItem.action === 'reject' ? 'var(--crimson)' : 'var(--amber)',
              background: stagedItem.action === 'approve' ? 'var(--jade-dim)' : stagedItem.action === 'reject' ? 'var(--crimson-dim)' : 'var(--amber-dim)',
            }}>
            <span>Staged for {stagedItem.action} — not yet committed</span>
            {onUnstage && (
              <button onClick={onUnstage} className="underline text-[10px] font-sans font-semibold hover:text-white">undo staged action</button>
            )}
          </div>
        )}

        {/* Zone 1 Narrative & Core Details */}
        <div className="space-y-4">
          
          {/* Evidence Artifacts (Primary Evidence) */}
          {finding.artifacts?.length > 0 && (
            <div className="space-y-2">
              <Label>PRIMARY EVIDENCE ARTIFACTS</Label>
              <div className="space-y-2">
                {finding.artifacts.map((art, idx) => (
                  <div key={idx} className="p-3 border rounded border-border-faint bg-bg-surface space-y-1.5 text-xs font-mono">
                    <div className="flex justify-between items-center text-[10px] text-text-muted">
                      <span className="font-bold text-text-primary">{art.source}</span>
                      {art.audit_id && <span>audit: {art.audit_id}</span>}
                    </div>
                    {art.extraction && (
                      <div className="text-[11px] text-cyan">$ {art.extraction}</div>
                    )}
                    {art.content && (
                      <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-bright overflow-x-auto whitespace-pre-wrap max-h-40">
                        {art.content}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Provenance Warnings */}
          {finding.provenance_warnings?.length > 0 && (
            <div className="p-3 rounded border text-xs bg-amber-dim border-amber text-amber font-mono space-y-1">
              <div className="font-bold">▲ PROVENANCE WARNINGS:</div>
              {finding.provenance_warnings.map((w, idx) => (
                <div key={idx}>• {w}</div>
              ))}
            </div>
          )}

          {/* Description */}
          {eff.description && (
            <div>
              <div className="flex items-center gap-1.5">
                <Label>DESCRIPTION</Label>
                {editingField !== 'description' && (
                  <button onClick={() => startEdit('description', eff.description)} className="text-text-muted hover:text-cyan text-[11px]">✎</button>
                )}
              </div>
              <EditableField
                field="description"
                value={eff.description}
                f={finding}
                de={stagedItem}
                editingField={editingField}
                editVal={editVal}
                setEditVal={setEditVal}
                saveEdit={saveEdit}
                cancelEdit={cancelEdit}
              />
            </div>
          )}

          {/* Narrative / Body */}
          {eff.body && (
            <div>
              <div className="flex items-center gap-1.5">
                <Label>NARRATIVE (BODY)</Label>
                {editingField !== 'body' && (
                  <button onClick={() => startEdit('body', eff.body)} className="text-text-muted hover:text-cyan text-[11px]">✎</button>
                )}
              </div>
              <EditableField
                field="body"
                value={eff.body}
                f={finding}
                de={stagedItem}
                editingField={editingField}
                editVal={editVal}
                setEditVal={setEditVal}
                saveEdit={saveEdit}
                cancelEdit={cancelEdit}
              />
            </div>
          )}

          {/* Observation (Fact) */}
          <div>
            <div className="flex items-center gap-1.5">
              <Label>OBSERVATION (FACT)</Label>
              {editingField !== 'observation' && (
                <button onClick={() => startEdit('observation', eff.observation)} className="text-text-muted hover:text-cyan text-[11px]">✎</button>
              )}
            </div>
            <EditableField
              field="observation"
              value={eff.observation}
              f={finding}
              de={stagedItem}
              editingField={editingField}
              editVal={editVal}
              setEditVal={setEditVal}
              saveEdit={saveEdit}
              cancelEdit={cancelEdit}
            />
          </div>

          {/* Interpretation (Opinion) */}
          <div>
            <div className="flex items-center gap-1.5">
              <Label>INTERPRETATION (ANALYSIS)</Label>
              {editingField !== 'interpretation' && (
                <button onClick={() => startEdit('interpretation', eff.interpretation)} className="text-text-muted hover:text-cyan text-[11px]">✎</button>
              )}
            </div>
            <EditableField
              field="interpretation"
              value={eff.interpretation}
              f={finding}
              de={stagedItem}
              editingField={editingField}
              editVal={editVal}
              setEditVal={setEditVal}
              saveEdit={saveEdit}
              cancelEdit={cancelEdit}
            />
          </div>

          {/* Confidence and Justification */}
          <div>
            <Label>CONFIDENCE & JUSTIFICATION</Label>
            <div className="flex flex-wrap items-center gap-2 mt-2 text-xs">
              {editingField === 'confidence' ? (
                <div className="flex gap-2 items-center">
                  <select value={editVal} onChange={(e) => setEditVal(e.target.value)}
                    className="px-2 py-0.5 rounded text-xs font-mono focus:outline-none"
                    style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}>
                    {['SPECULATIVE', 'LOW', 'MEDIUM', 'HIGH'].map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                  <button onClick={() => saveEdit('confidence')} className="px-2 py-0.5 rounded text-xs font-sans font-semibold"
                    style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>Save</button>
                  <button onClick={cancelEdit} className="px-2 py-0.5 rounded text-xs font-sans"
                    style={{ color: 'var(--text-muted)' }}>Cancel</button>
                </div>
              ) : (
                <button onClick={() => startEdit('confidence', eff.confidence)} className="flex items-center gap-1 hover:opacity-85">
                  {stagedItem?.modifications?.confidence ? (
                    <span className="flex items-center gap-1 font-mono text-[10px] text-text-muted line-through">
                      {stagedItem.modifications.confidence.original}
                    </span>
                  ) : null}
                  <Badge color={CONF_COLOR[eff.confidence] ?? 'var(--text-muted)'}>
                    {CONF_SHAPE[eff.confidence]} {eff.confidence} ✎
                  </Badge>
                </button>
              )}

              {/* Justification Text */}
              {editingField === 'confidence_justification' ? (
                <div className="flex flex-col gap-2 flex-1 mt-1">
                  <textarea value={editVal} onChange={(e) => setEditVal(e.target.value)}
                    rows={3}
                    className="w-full p-2 rounded text-xs font-sans focus:outline-none resize-y"
                    style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => saveEdit('confidence_justification')} className="px-2 py-0.5 rounded text-xs font-sans font-semibold"
                      style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>Save</button>
                    <button onClick={cancelEdit} className="px-2 py-0.5 rounded text-xs font-sans"
                      style={{ color: 'var(--text-muted)' }}>Cancel</button>
                  </div>
                </div>
              ) : (
                <div className="flex items-start gap-1.5 flex-1 min-w-0">
                  <span className="font-sans text-xs italic text-text-primary break-words whitespace-pre-wrap flex-1">
                    — {eff.confidence_justification || <span style={{ color: 'var(--text-muted)' }}>No confidence justification.</span>}
                  </span>
                  <button onClick={() => startEdit('confidence_justification', eff.confidence_justification)} className="text-text-muted hover:text-cyan text-[11px] shrink-0 mt-0.5" title="Edit justification">✎</button>
                </div>
              )}
            </div>
          </div>

          {/* Context Section (Collapsible) */}
          <div className="border border-border-faint rounded overflow-hidden">
            <button onClick={() => setShowContext(!showContext)} className="w-full text-left px-3 py-2 text-xs font-sans flex items-center justify-between bg-bg-surface hover:bg-bg-raised text-text-primary">
              <span className="flex items-center gap-2">
                <span className="text-[10px] text-text-muted">{showContext ? '▼' : '▶'}</span>
                <span className="font-semibold">Examiner Context Notes</span>
              </span>
            </button>
            {showContext && (
              <div className="p-3 bg-bg-surface border-t border-border-faint space-y-2">
                <div className="flex items-center justify-between">
                  <Label>CONTEXT SUMMARY</Label>
                  {editingField !== 'context' && (
                    <button onClick={() => startEdit('context', eff.context)} className="text-text-muted hover:text-cyan text-[11px]">✎ Edit Context</button>
                  )}
                </div>
                <EditableField
                  field="context"
                  value={eff.context}
                  f={finding}
                  de={stagedItem}
                  editingField={editingField}
                  editVal={editVal}
                  setEditVal={setEditVal}
                  saveEdit={saveEdit}
                  cancelEdit={cancelEdit}
                />
              </div>
            )}
          </div>

          {/* Meta Bar */}
          <div className="text-[10px] font-mono p-2 border-t border-border-faint text-text-muted flex flex-wrap gap-x-3 gap-y-1">
            {finding.host && <span>HOST: {finding.host}</span>}
            {(finding.affected_account || finding.account) && <span>ACCOUNT: {finding.affected_account || finding.account}</span>}
            {finding.event_type && <span>EVENT TYPE: {finding.event_type}</span>}
            {finding.source_evidence && <span>SOURCE: {finding.source_evidence}</span>}
            {finding.timeline_event_id && (
              <span className="text-cyan cursor-pointer hover:underline" onClick={() => navigateToFinding(finding.timeline_event_id)}>
                TIMELINE ID: {finding.timeline_event_id}
              </span>
            )}
            {finding.created_by && <span>STAGED BY: {finding.created_by}</span>}
          </div>
        </div>

        {/* Zone 2 Evidence & Context (Collapsible Details) */}
        <details className="group border border-border-faint rounded" open={zone2Open} onToggle={(e) => setZone2Open(e.target.open)}>
          <summary className="px-3 py-2 text-xs font-semibold cursor-pointer select-none flex items-center bg-bg-surface hover:bg-bg-raised text-text-primary list-none [&::-webkit-details-marker]:hidden">
            <span className="flex items-center gap-2">
              <span className="text-[10px] text-text-muted">{zone2Open ? '▼' : '▶'}</span>
              <span>Evidence & Context Detail</span>
            </span>
          </summary>
          
          <div className="flex flex-col md:flex-row gap-5 p-4 border-t border-border-faint bg-bg-base">
            
            {/* Zone 2 Left column */}
            <div className="flex-1 space-y-4">
              
              {/* Duplicate Evidence list */}
              {finding.artifacts?.length > 0 && (
                <div>
                  <Label>EVIDENCE FILES & EXTRACTS</Label>
                  <div className="mt-2 space-y-2">
                    {finding.artifacts.map((art, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-bg-surface border border-border-faint space-y-1 text-xs">
                        <div className="font-mono text-text-bright font-semibold truncate">{art.source}</div>
                        <div className="font-mono text-cyan text-[11px]">$ {art.extraction || 'N/A'}</div>
                        {art.content_type && (
                          <span className="px-1.5 py-0.5 rounded font-mono text-[9px] bg-bg-raised text-text-muted border border-border-faint">
                            {art.content_type}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Supporting commands */}
              {finding.supporting_commands?.length > 0 && (
                <div>
                  <Label>SUPPORTING COMMAND EXECUTION</Label>
                  <div className="mt-2 space-y-2">
                    {finding.supporting_commands.map((cmd, idx) => (
                      <div key={idx} className="p-3 border rounded border-border-faint bg-bg-surface space-y-1.5 text-xs font-mono">
                        <div className="text-text-muted text-[10px] font-bold">shell exec output</div>
                        <div className="text-cyan">$ {cmd.command}</div>
                        {cmd.output_excerpt && (
                          <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-bright overflow-x-auto whitespace-pre-wrap max-h-40">
                            {cmd.output_excerpt}
                          </pre>
                        )}
                        {cmd.purpose && <div className="text-text-muted italic">Purpose: {cmd.purpose}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Full Audit Trail */}
              {finding.audit_ids?.length > 0 && (
                <div>
                  {loadingAudit ? (
                    <div className="text-xs font-mono text-text-muted animate-pulse">Loading audit trail…</div>
                  ) : (
                    <AuditTrailPanel auditData={auditData} finding={finding} />
                  )}
                </div>
              )}
            </div>

            {/* Zone 2 Right column */}
            <div className="w-full md:w-80 shrink-0 space-y-4 border-t md:border-t-0 md:border-l border-border-faint pt-4 md:pt-0 md:pl-5">
              
              {/* Timeline Context (±2h) */}
              {contextEvents.length > 0 && (
                <div>
                  <Label>TIMELINE CONTEXT (±2h)</Label>
                  <div className="mt-2 space-y-1 max-h-48 overflow-y-auto pr-1">
                    {contextEvents.map((ev) => {
                      const isThis = ev.finding_refs?.includes(finding.id)
                      return (
                        <div key={ev.id} className="flex items-start gap-2 text-[10px] font-mono px-2 py-1 rounded"
                          style={{ background: isThis ? 'var(--cyan-dim)' : 'transparent', color: isThis ? 'var(--cyan)' : 'var(--text-muted)' }}>
                          <span className="shrink-0">{new Date(ev.timestamp).toISOString().substring(11, 19)}</span>
                          <span className="w-12 shrink-0 truncate" style={{ color: 'var(--text-muted)' }}>[{ev.type}]</span>
                          <span className="truncate flex-1" style={{ color: isThis ? 'var(--cyan)' : 'var(--text-primary)' }}>{ev.description}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Audit IDs */}
              {finding.audit_ids?.length > 0 && (
                <div>
                  <Label>AUDIT KEYS</Label>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {finding.audit_ids.map(eid => (
                      <span key={eid} className="px-2 py-0.5 rounded font-mono text-[10px] bg-bg-surface text-text-primary border border-border-soft">
                        {eid}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK */}
              <div>
                <div className="flex items-center justify-between">
                  <Label>MITRE ATT&CK Mapping</Label>
                  {editingField !== 'mitre_ids' && (
                    <button onClick={() => startEdit('mitre_ids', eff.mitre_ids)} className="text-text-muted hover:text-cyan text-xs">✎</button>
                  )}
                </div>
                <EditableField
                  field="mitre_ids"
                  value={eff.mitre_ids}
                  f={finding}
                  de={stagedItem}
                  editingField={editingField}
                  editTags={editTags}
                  setEditTags={setEditTags}
                  saveEdit={saveEdit}
                  cancelEdit={cancelEdit}
                />
              </div>

              {/* IOCs */}
              <div>
                <div className="flex items-center justify-between">
                  <Label>Indicators of Compromise</Label>
                  {editingField !== 'iocs' && (
                    <button onClick={() => startEdit('iocs', eff.iocs)} className="text-text-muted hover:text-cyan text-xs">✎</button>
                  )}
                </div>
                <EditableField
                  field="iocs"
                  value={eff.iocs}
                  f={finding}
                  de={stagedItem}
                  editingField={editingField}
                  editTags={editTags}
                  setEditTags={setEditTags}
                  saveEdit={saveEdit}
                  cancelEdit={cancelEdit}
                />
              </div>

              {/* Tags (Read-only) */}
              {finding.tags?.length > 0 && (
                <div>
                  <Label>Tags</Label>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {finding.tags.map(t => (
                      <span key={t} className="px-2 py-0.5 rounded font-mono text-[10px] bg-bg-surface text-text-muted border border-border-faint">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Related findings */}
              {finding.related_findings?.length > 0 && (
                <div>
                  <Label>Related Findings</Label>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {finding.related_findings.map(rid => (
                      <button key={rid} onClick={() => navigateToFinding(rid)}
                        className="px-2 py-0.5 rounded font-mono text-[10px] bg-bg-surface text-cyan border border-cyan hover:bg-cyan-dim">
                        [{rid}]
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Artifact Reference */}
              {finding.artifact_ref && (
                <div>
                  <Label>Artifact Reference</Label>
                  <div className="mt-1 text-xs font-mono text-text-primary break-all">
                    {finding.artifact_ref}
                  </div>
                </div>
              )}

              {/* Integrity */}
              <details className="group border border-border-faint rounded p-2.5">
                <summary className="text-[11px] font-semibold cursor-pointer select-none text-text-muted flex items-center gap-2 list-none [&::-webkit-details-marker]:hidden">
                  <span className="text-[10px] text-text-muted">
                    <span className="group-open:hidden">▶</span>
                    <span className="hidden group-open:inline">▼</span>
                  </span>
                  <span>Cryptographic Integrity</span>
                </summary>
                <div className="mt-2 space-y-1 text-[10px] font-mono text-text-muted">
                  <div>Verification: <span className={clsx(
                    finding.verification === 'confirmed' ? 'text-jade' : 'text-amber'
                  )}>{finding.verification || 'draft'}</span></div>
                  <div>Provenance: <span>{finding.provenance || 'NONE'}</span></div>
                  {finding.content_hash && (
                    <div className="truncate">Content hash: {finding.content_hash.slice(0, 16)}...</div>
                  )}
                  {finding.modified_at && (
                    <div>Modified: {finding.modified_at}</div>
                  )}
                </div>
              </details>

            </div>
          </div>
        </details>

        {/* Examiner notes (Review History / Notes) */}
        {finding.examiner_notes?.length > 0 && (
          <div className="p-3 border border-border-faint rounded bg-bg-surface space-y-2">
            <Label>EXAMINER NOTES LOG</Label>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {finding.examiner_notes.map((n, idx) => (
                <div key={idx} className="text-xs p-2 rounded bg-bg-raised border border-border-faint">
                  <div className="flex justify-between items-center text-[10px] text-text-muted mb-1">
                    <span className="font-bold text-text-primary">{n.by}</span>
                    <span>{n.at ? new Date(n.at).toLocaleString() : ''}</span>
                  </div>
                  <div className="text-text-primary font-sans leading-normal whitespace-pre-wrap">{n.note || n.text}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Modifications History */}
        {finding.examiner_modifications && Object.keys(finding.examiner_modifications).length > 0 && (
          <div className="p-3 border border-border-faint rounded bg-bg-surface space-y-2">
            <Label>MODIFICATION LOG</Label>
            <div className="space-y-1 text-xs">
              {Object.entries(finding.examiner_modifications).map(([field, mod]) => (
                <div key={field} className="p-1.5 rounded bg-bg-raised border border-border-faint">
                  <div className="font-bold font-mono text-[10px] text-text-muted capitalize">{field}</div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="line-through text-text-muted">{String(mod.original || '(empty)')}</span>
                    <span className="text-text-muted">→</span>
                    <span className="text-text-bright font-semibold">{String(mod.modified || '(empty)')}</span>
                    {mod.modified_by && <span className="text-[10px] text-text-muted ml-auto">by {mod.modified_by}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Approval / Rejection Audit Trail */}
        {(finding.approved_by || finding.rejected_by) && (
          <div className="p-3 border border-border-faint rounded bg-bg-surface space-y-1.5 text-xs text-text-muted font-sans">
            {finding.approved_by && (
              <div>
                ✓ APPROVED BY <strong style={{ color: 'var(--jade)' }}>{finding.approved_by}</strong>
                {finding.approved_at && ` at ${new Date(finding.approved_at).toLocaleString()}`}
              </div>
            )}
            {finding.rejected_by && (
              <div>
                ✗ REJECTED BY <strong style={{ color: 'var(--crimson)' }}>{finding.rejected_by}</strong>
                {finding.rejected_at && ` at ${new Date(finding.rejected_at).toLocaleString()}`}
              </div>
            )}
            {finding.rejection_reason && (
              <div className="p-2 rounded bg-bg-void border border-border-faint mt-1 text-text-primary font-mono text-xs">
                Reason: {finding.rejection_reason}
              </div>
            )}
          </div>
        )}

      </div>

      {/* Action bar (BUG-14) */}
      <div className="shrink-0 p-3 flex gap-2 border-t" style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-surface)' }}>
        {stagedItem ? (
          <ActionBtn color="var(--amber)" bg="var(--amber-dim)" onClick={onUnstage}>↩ Undo staged {stagedItem.action}</ActionBtn>
        ) : (
          <>
            {finding.status?.toLowerCase() !== 'approved' && (
              <ActionBtn color="var(--jade)" bg="var(--jade-dim)" onClick={onApprove}>✓ Approve</ActionBtn>
            )}
            {finding.status?.toLowerCase() !== 'rejected' && (
              <ActionBtn color="var(--crimson)" bg="var(--crimson-dim)" onClick={onReject}>✗ Reject</ActionBtn>
            )}
          </>
        )}
        <div className="flex-1" />
        <span className="text-[11px] font-mono self-center" style={{ color: 'var(--text-muted)' }}>
          j/k navigate · a approve · r reject
        </span>
      </div>
    </div>
  )
}

function EditableField({ field, label, value, f, de, editingField, editVal, setEditVal, editTags, setEditTags, saveEdit, cancelEdit }) {
  const isEditing = editingField === field
  const hasMod = de?.modifications?.[field]
  
  if (isEditing) {
    if (field === 'mitre_ids' || field === 'iocs') {
      const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
          e.preventDefault()
          const val = e.target.value.trim()
          if (val && !editTags.map(getTagString).includes(val)) {
            setEditTags([...editTags, val])
            e.target.value = ''
          }
        }
      }
      
      const removeTag = (t) => {
        setEditTags(editTags.filter(x => getTagString(x) !== getTagString(t)))
      }
      
      return (
        <div className="mt-1 space-y-2">
          <div className="flex flex-wrap gap-1.5 p-2 rounded" style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)' }}>
            {editTags.map(t => {
              const strVal = getTagString(t)
              return (
                <span key={strVal} className="flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px]"
                  style={{ background: 'var(--bg-overlay)', color: 'var(--text-primary)', border: '1px solid var(--border-faint)' }}>
                  {strVal}
                  <button type="button" onClick={() => removeTag(t)} className="text-crimson hover:text-white font-bold">&times;</button>
                </span>
              )
            })}
            <input type="text" placeholder="Add + Enter" onKeyDown={handleKeyDown}
              className="bg-transparent focus:outline-none text-[11px] font-mono text-text-bright w-24" />
          </div>
          <div className="flex gap-2">
            <button onClick={() => saveEdit(field)} className="px-2 py-0.5 rounded text-xs font-sans font-semibold"
              style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>Save</button>
            <button onClick={cancelEdit} className="px-2 py-0.5 rounded text-xs font-sans"
              style={{ color: 'var(--text-muted)' }}>Cancel</button>
          </div>
        </div>
      )
    }
    
    const rows = field === 'context' ? 5 : 3
    const placeholder = field === 'context'
      ? "Add examiner context: data exposure, business impact, third-party relevance, chain of custody notes, or any finding-specific observations the report should reflect."
      : `Edit ${label || field}...`

    return (
      <div className="mt-1 space-y-2 font-sans w-full">
        <textarea rows={rows} value={editVal} onChange={(e) => setEditVal(e.target.value)} placeholder={placeholder}
          className="w-full p-2 rounded text-xs focus:outline-none"
          style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
        <div className="flex gap-2">
          <button onClick={() => saveEdit(field)} className="px-2 py-0.5 rounded text-xs font-sans font-semibold"
            style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>Save</button>
          <button onClick={cancelEdit} className="px-2 py-0.5 rounded text-xs font-sans"
            style={{ color: 'var(--text-muted)' }}>Cancel</button>
        </div>
      </div>
    )
  }
  
  // Display mode
  if (hasMod) {
    const originalVal = hasMod.original
    const modifiedVal = hasMod.modified
    
    if (field === 'mitre_ids' || field === 'iocs') {
      return (
        <div className="mt-1 space-y-1 font-mono text-xs">
          <div className="line-through text-text-muted flex flex-wrap gap-1">
            {Array.isArray(originalVal) ? originalVal.map(t => {
              const strVal = getTagString(t)
              return <span key={strVal} className="px-1.5 py-0.5 rounded bg-bg-raised border border-border-faint">{strVal}</span>
            }) : String(originalVal)}
          </div>
          <div className="text-amber flex flex-wrap gap-1">
            {Array.isArray(modifiedVal) ? modifiedVal.map(t => {
              const strVal = getTagString(t)
              return <span key={strVal} className="px-1.5 py-0.5 rounded bg-bg-raised border border-amber">{strVal}</span>
            }) : String(modifiedVal)}
          </div>
        </div>
      )
    }
    
    return (
      <div className="mt-1 text-xs">
        <div className="line-through text-text-muted font-sans text-xs mb-1">{String(originalVal || '(empty)')}</div>
        <div className="text-amber font-sans text-xs font-semibold">{String(modifiedVal || '(empty)')}</div>
      </div>
    )
  }
  
  if (field === 'mitre_ids' || field === 'iocs') {
    const items = Array.isArray(value) ? value : []
    if (items.length === 0) {
      return <div className="mt-1 text-xs font-mono italic" style={{ color: 'var(--text-muted)' }}>None.</div>
    }
    return (
      <div className="mt-1 flex flex-wrap gap-1.5">
        {items.map(t => {
          const strVal = getTagString(t)
          return (
            <span key={strVal} className="px-2 py-0.5 rounded font-mono text-[11px]"
              style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--border-faint)' }}>
              {strVal}
            </span>
          )
        })}
      </div>
    )
  }
  
  return (
    <div className="mt-1 text-xs font-sans leading-relaxed whitespace-pre-wrap" style={{ color: 'var(--text-primary)' }}>
      {value ? String(value) : <span style={{ color: 'var(--text-muted)' }}>Empty.</span>}
    </div>
  )
}

function AuditTrailPanel({ auditData, finding }) {
  const eids = finding.audit_ids || []
  const [openIds, setOpenIds] = useState(new Set(eids.slice(0, 1)))

  const toggleOpen = (eid) => {
    setOpenIds(prev => {
      const next = new Set(prev)
      if (next.has(eid)) next.delete(eid)
      else next.add(eid)
      return next
    })
  }

  const toggleAll = () => {
    const allOpen = eids.every(id => openIds.has(id))
    if (allOpen) {
      setOpenIds(new Set())
    } else {
      setOpenIds(new Set(eids))
    }
  }

  const renderResultSummary = (summary) => {
    if (!summary) return 'No result summary available.'
    if (typeof summary === 'string') return summary
    
    return (
      <div className="space-y-1 mt-1 text-[11px] font-mono">
        {summary.exit_code !== undefined && (
          <div>
            <span className="text-text-muted">Exit:</span>{' '}
            <span className={summary.exit_code === 0 ? 'text-jade' : 'text-crimson'}>
              {summary.exit_code}
            </span>
          </div>
        )}
        {summary.output_file && (
          <div>
            <span className="text-text-muted">File:</span>{' '}
            <span className="text-text-bright">{summary.output_file}</span>
          </div>
        )}
        {summary.output_sha256 && (
          <div>
            <span className="text-text-muted">SHA-256:</span>{' '}
            <span className="text-text-bright">{summary.output_sha256.slice(0, 16)}...</span>
          </div>
        )}
        {summary.stdout_bytes && (
          <div>
            <span className="text-text-muted">Size:</span>{' '}
            <span>{summary.stdout_bytes} bytes</span>
          </div>
        )}
        {summary.stdout_head && (
          <div>
            <span className="text-text-muted">Output:</span>
            <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-primary whitespace-pre-wrap max-h-40 overflow-y-auto mt-1">
              {summary.stdout_head}
            </pre>
          </div>
        )}
      </div>
    )
  }

  if (eids.length === 0) return null

  // Group audit entries by audit_id
  const byEid = {}
  auditData.forEach(entry => {
    const eid = entry.audit_id || ''
    if (!byEid[eid]) byEid[eid] = []
    byEid[eid].push(entry)
  })

  const allOpen = eids.every(id => openIds.has(id))

  return (
    <div className="border border-border-faint rounded p-3 bg-bg-surface space-y-2 mt-4">
      <div className="flex justify-between items-center pb-2 border-b border-border-faint">
        <span className="text-[10px] font-sans font-semibold tracking-wider text-text-muted uppercase">Full Audit Trail</span>
        <button onClick={toggleAll} className="text-[10px] text-cyan hover:underline font-mono">
          {allOpen ? 'collapse all' : 'expand all'}
        </button>
      </div>
      <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
        {eids.map(eid => {
          const entries = byEid[eid] || []
          const entry = entries[0] || {}
          const backend = entry._backend || 'unknown'
          const isOpen = openIds.has(eid)
          
          const isShell = backend.includes('exec') || (entry.mcp || '').includes('shell') || (entry.source || '').includes('shell')

          return (
            <div key={eid} className="border border-border-soft rounded overflow-hidden">
              <button onClick={() => toggleOpen(eid)} className="w-full text-left px-3 py-2 text-xs font-mono flex items-center justify-between bg-bg-raised hover:bg-bg-overlay text-text-primary">
                <span className="flex items-center gap-2">
                  <span className="text-[10px] text-text-muted">{isOpen ? '▼' : '▶'}</span>
                  <span className="font-bold">{eid}</span>
                  <span className="text-text-muted">({backend})</span>
                </span>
              </button>
              {isOpen && (
                <div className="p-3 bg-bg-surface border-t border-border-soft space-y-2 font-mono text-[11px] text-text-primary">
                  {isShell ? (
                    <>
                      {entry.params?.command && (
                        <div>
                          <span className="text-text-muted font-bold block mb-1">Command:</span>
                          <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-bright overflow-x-auto whitespace-pre-wrap">{entry.params.command}</pre>
                        </div>
                      )}
                      {entry.result_summary && (
                        <div>
                          <span className="text-text-muted font-bold block mb-1">Output:</span>
                          {renderResultSummary(entry.result_summary)}
                        </div>
                      )}
                      {entry.params?.purpose && (
                        <div>
                          <span className="text-text-muted font-bold">Purpose:</span>{' '}
                          <span className="text-text-bright">{entry.params.purpose}</span>
                        </div>
                      )}
                    </>
                  ) : (
                    <>
                      {entry.tool && (
                        <div>
                          <span className="text-text-muted font-bold">Tool:</span>{' '}
                          <span className="text-text-bright">{entry.tool}</span>
                        </div>
                      )}
                      {entry.params && (
                        <div>
                          <span className="text-text-muted font-bold block mb-1">Params:</span>
                          <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-bright overflow-x-auto whitespace-pre-wrap">{JSON.stringify(entry.params, null, 2)}</pre>
                        </div>
                      )}
                      {entry.result_summary && (
                        <div>
                          <span className="text-text-muted font-bold block mb-1">Result:</span>
                          {renderResultSummary(entry.result_summary)}
                        </div>
                      )}
                      {entry.elapsed_ms && (
                        <div>
                          <span className="text-text-muted font-bold font-mono">Elapsed:</span>{' '}
                          <span>{entry.elapsed_ms}ms</span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function Badge({ color, subtle, children }) {
  return (
    <span className="px-1.5 py-0.5 rounded font-mono text-[10px] tracking-wider uppercase"
      style={{
        color,
        background: subtle ? 'var(--bg-raised)' : color + '22',
        border: `1px solid ${color}44`,
      }}>
      {children}
    </span>
  )
}

function Label({ children }) {
  return (
    <p className="text-[10px] font-sans font-semibold tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>
      {children}
    </p>
  )
}

function ActionBtn({ color, bg, onClick, children }) {
  return (
    <button onClick={onClick} className="px-4 py-1.5 rounded text-xs font-sans font-semibold transition-opacity hover:opacity-80 border"
      style={{ background: bg, color, borderColor: color }}>
      {children}
    </button>
  )
}
