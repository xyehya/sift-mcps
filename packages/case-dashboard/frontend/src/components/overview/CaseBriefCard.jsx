import { useState } from 'react'
import { useStoreSlice } from '../../store/useStore'
import { postCaseMetadata, getCase } from '../../api/endpoints'

// Mirror of the examiner-settable schema in sift_core/case_metadata.py.
const INCIDENT_TYPES = [
  'ransomware', 'bec', 'data_breach', 'insider_threat', 'supply_chain',
  'malware', 'unauthorized_access', 'dos', 'other',
]
const SEVERITIES = ['critical', 'high', 'medium', 'low']
const TLPS = ['WHITE', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED']
const DATE_FIELDS = [
  ['occurred_at', 'Occurred'],
  ['detected_at', 'Detected'],
  ['reported_at', 'Reported'],
  ['contained_at', 'Contained'],
  ['eradicated_at', 'Eradicated'],
  ['recovered_at', 'Recovered'],
]
const TEXT_FIELDS = [
  ['client', 'Client'],
  ['point_of_contact', 'Point of contact'],
  ['lead_examiner', 'Lead examiner'],
]
// List fields: textarea ⇒ one item per line; chips ⇒ comma-separated.
const LINE_LIST_FIELDS = [
  ['affected_systems', 'Affected systems'],
  ['affected_accounts', 'Affected accounts'],
]
const COMMA_LIST_FIELDS = [
  ['tags', 'Tags'],
  ['related_cases', 'Related cases'],
  ['distribution_list', 'Distribution list'],
]

function toDatetimeLocal(iso) {
  if (!iso) return ''
  // Accept "YYYY-MM-DD" or full ISO → render as "YYYY-MM-DDTHH:MM"
  try {
    const d = new Date(iso)
    if (isNaN(d)) return ''
    const pad = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  } catch { return '' }
}

function asList(val) {
  return Array.isArray(val) ? val : (val ? [val] : [])
}

export function CaseBriefCard() {
  const { activeCase, user, setActiveCase, addToast } = useStoreSlice((state) => ({
    activeCase: state.activeCase,
    user: state.user,
    setActiveCase: state.setActiveCase,
    addToast: state.addToast,
  }))
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState({})

  if (!activeCase) return null
  const isExaminer = (user?.role || '').toLowerCase() === 'examiner'
  const meta = activeCase

  const hasBrief =
    meta.description || meta.incident_type || meta.severity || meta.impact_summary ||
    asList(meta.affected_systems).length || asList(meta.affected_accounts).length ||
    DATE_FIELDS.some(([k]) => meta[k]) || TEXT_FIELDS.some(([k]) => meta[k])

  function openEdit() {
    const f = {
      incident_type: meta.incident_type || '',
      severity: meta.severity || '',
      tlp: meta.tlp || '',
      impact_summary: meta.impact_summary || '',
    }
    TEXT_FIELDS.forEach(([k]) => { f[k] = meta[k] || '' })
    DATE_FIELDS.forEach(([k]) => { f[k] = toDatetimeLocal(meta[k]) })
    LINE_LIST_FIELDS.forEach(([k]) => { f[k] = asList(meta[k]).join('\n') })
    COMMA_LIST_FIELDS.forEach(([k]) => { f[k] = asList(meta[k]).join(', ') })
    setForm(f)
    setEditing(true)
  }

  function setField(k, v) { setForm((prev) => ({ ...prev, [k]: v })) }

  // Build the list of {field, value} changes vs. current metadata.
  function buildChanges() {
    const changes = []
    const scalar = ['incident_type', 'severity', 'tlp', 'impact_summary', ...TEXT_FIELDS.map(([k]) => k)]
    scalar.forEach((k) => {
      const v = (form[k] ?? '').trim()
      if (v && v !== (meta[k] || '')) changes.push({ field: k, value: k === 'tlp' ? v.toUpperCase() : v })
    })
    DATE_FIELDS.forEach(([k]) => {
      const v = (form[k] ?? '').trim()
      if (v) {
        const iso = new Date(v).toISOString()
        if (iso !== (meta[k] ? new Date(meta[k]).toISOString() : '')) changes.push({ field: k, value: iso })
      }
    })
    LINE_LIST_FIELDS.forEach(([k]) => {
      const arr = (form[k] ?? '').split('\n').map((s) => s.trim()).filter(Boolean)
      if (JSON.stringify(arr) !== JSON.stringify(asList(meta[k]))) changes.push({ field: k, value: arr })
    })
    COMMA_LIST_FIELDS.forEach(([k]) => {
      const arr = (form[k] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
      if (JSON.stringify(arr) !== JSON.stringify(asList(meta[k]))) changes.push({ field: k, value: arr })
    })
    return changes
  }

  async function save(e) {
    e.preventDefault()
    const changes = buildChanges()
    if (changes.length === 0) { setEditing(false); return }
    setSaving(true)
    let failed = 0
    for (const c of changes) {
      try {
        const res = await postCaseMetadata(c)
        if (res?.error) { failed++; addToast(`${c.field}: ${res.error}`, 'error') }
      } catch (ex) {
        failed++
        let msg = ex?.message || 'save failed'
        try { msg = JSON.parse(ex.message).error || msg } catch { /* keep raw */ }
        addToast(`${c.field}: ${msg}`, 'error')
      }
    }
    // Refresh the active case from CASE.yaml so the card reflects saved values now.
    try { const fresh = await getCase(); if (fresh) setActiveCase(fresh) } catch { /* polling will catch up */ }
    setSaving(false)
    if (failed === 0) { addToast('Case brief updated', 'success'); setEditing(false) }
  }

  return (
    <div className="mb-4 p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-sans font-semibold tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>
          CASE BRIEF
        </p>
        {isExaminer && (
          <button onClick={openEdit}
            className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
            style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', borderColor: 'var(--cyan)' }}>
            Edit brief
          </button>
        )}
      </div>

      {!hasBrief ? (
        <p className="mt-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          No case brief recorded yet.{isExaminer ? ' Use “Edit brief” to capture scope, incident type, severity, affected systems/accounts, and key dates.' : ''}
        </p>
      ) : (
        <div className="mt-3 space-y-3">
          {meta.description && (
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-primary)' }}>{meta.description}</p>
          )}
          <div className="flex flex-wrap gap-1.5">
            {meta.incident_type && <Chip label={meta.incident_type} />}
            {meta.severity && <Chip label={`severity: ${meta.severity}`} accent="var(--amber)" />}
            {meta.tlp && <Chip label={`TLP:${meta.tlp}`} accent="var(--violet)" />}
            {asList(meta.tags).map((t) => <Chip key={t} label={t} />)}
          </div>
          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono">
            {TEXT_FIELDS.map(([k, lbl]) => meta[k] && (<Row key={k} label={lbl} value={meta[k]} />))}
            {DATE_FIELDS.map(([k, lbl]) => meta[k] && (<Row key={k} label={lbl} value={new Date(meta[k]).toLocaleString()} />))}
            {asList(meta.affected_systems).length > 0 && <Row label="Systems" value={asList(meta.affected_systems).join(', ')} />}
            {asList(meta.affected_accounts).length > 0 && <Row label="Accounts" value={asList(meta.affected_accounts).join(', ')} />}
          </div>
          {meta.impact_summary && (
            <div>
              <p className="text-[10px] font-sans uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Impact</p>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-primary)' }}>{meta.impact_summary}</p>
            </div>
          )}
        </div>
      )}

      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(7,9,14,0.8)' }}
          onClick={() => !saving && setEditing(false)}>
          <form onSubmit={save} onClick={(e) => e.stopPropagation()}
            className="w-full max-w-2xl max-h-[88vh] overflow-y-auto p-6 rounded-lg space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-soft)' }}>
            <h2 className="text-sm font-sans font-semibold" style={{ color: 'var(--text-bright)' }}>Edit case brief</h2>

            {meta.description && (
              <div>
                <FieldLabel>Synopsis (set at creation, read-only)</FieldLabel>
                <p className="text-xs leading-relaxed px-3 py-2 rounded" style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--border-faint)' }}>{meta.description}</p>
              </div>
            )}

            <div className="grid grid-cols-3 gap-3">
              <Select label="Incident type" value={form.incident_type} onChange={(v) => setField('incident_type', v)} options={INCIDENT_TYPES} />
              <Select label="Severity" value={form.severity} onChange={(v) => setField('severity', v)} options={SEVERITIES} />
              <Select label="TLP" value={form.tlp} onChange={(v) => setField('tlp', v)} options={TLPS} />
            </div>

            <div className="grid grid-cols-3 gap-3">
              {TEXT_FIELDS.map(([k, lbl]) => (
                <Text key={k} label={lbl} value={form[k]} onChange={(v) => setField(k, v)} />
              ))}
            </div>

            <div className="grid grid-cols-3 gap-3">
              {DATE_FIELDS.map(([k, lbl]) => (
                <DateInput key={k} label={lbl} value={form[k]} onChange={(v) => setField(k, v)} />
              ))}
            </div>

            <div className="grid grid-cols-2 gap-3">
              {LINE_LIST_FIELDS.map(([k, lbl]) => (
                <Area key={k} label={`${lbl} (one per line)`} value={form[k]} onChange={(v) => setField(k, v)} rows={3} />
              ))}
            </div>

            <div className="grid grid-cols-3 gap-3">
              {COMMA_LIST_FIELDS.map(([k, lbl]) => (
                <Text key={k} label={`${lbl} (comma-separated)`} value={form[k]} onChange={(v) => setField(k, v)} />
              ))}
            </div>

            <Area label="Impact summary" value={form.impact_summary} onChange={(v) => setField('impact_summary', v)} rows={3} />

            <div className="flex gap-2 pt-1">
              <button type="submit" disabled={saving}
                className="px-4 py-1.5 rounded text-xs font-sans font-semibold disabled:opacity-60"
                style={{ background: 'var(--cyan)', color: 'var(--bg-base)' }}>
                {saving ? 'Saving…' : 'Save brief'}
              </button>
              <button type="button" disabled={saving} onClick={() => setEditing(false)}
                className="px-3 py-1.5 rounded text-xs font-sans"
                style={{ border: '1px solid var(--border-soft)', color: 'var(--text-muted)' }}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}

function Chip({ label, accent }) {
  return (
    <span className="px-2 py-0.5 rounded font-mono text-[11px]"
      style={{ background: 'var(--bg-raised)', color: accent || 'var(--text-primary)', border: '1px solid var(--border-soft)' }}>
      {label}
    </span>
  )
}
function Row({ label, value }) {
  return (<><span style={{ color: 'var(--text-muted)' }}>{label}</span><span style={{ color: 'var(--text-primary)' }}>{value}</span></>)
}
function FieldLabel({ children }) {
  return <span className="block text-[10px] font-sans uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>{children}</span>
}
const inputStyle = { background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }
function Select({ label, value, onChange, options }) {
  return (
    <label className="block"><FieldLabel>{label}</FieldLabel>
      <select value={value || ''} onChange={(e) => onChange(e.target.value)}
        className="w-full px-2 py-1.5 rounded text-xs font-mono" style={inputStyle}>
        <option value="">—</option>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )
}
function Text({ label, value, onChange }) {
  return (
    <label className="block"><FieldLabel>{label}</FieldLabel>
      <input type="text" value={value || ''} onChange={(e) => onChange(e.target.value)}
        className="w-full px-2 py-1.5 rounded text-xs font-sans" style={inputStyle} />
    </label>
  )
}
function DateInput({ label, value, onChange }) {
  return (
    <label className="block"><FieldLabel>{label}</FieldLabel>
      <input type="datetime-local" value={value || ''} onChange={(e) => onChange(e.target.value)}
        className="w-full px-2 py-1.5 rounded text-xs font-mono" style={inputStyle} />
    </label>
  )
}
function Area({ label, value, onChange, rows }) {
  return (
    <label className="block"><FieldLabel>{label}</FieldLabel>
      <textarea value={value || ''} onChange={(e) => onChange(e.target.value)} rows={rows || 3}
        className="w-full px-2 py-1.5 rounded text-xs font-sans resize-y" style={inputStyle} />
    </label>
  )
}
