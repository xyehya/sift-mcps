// ─────────────────────────────────────────────────────────────────────────
// Reports — pure helpers: report profiles, date formatters, the client-side
// markdown serializer, and saved-report versioning. No JSX / no store, so the
// serializer + version logic stay unit-testable and the component files keep
// under react-refresh's only-export-components rule.
//
// SECURITY: this module only ever produces PLAIN STRINGS. The rendered preview
// (ReportRenderedView) renders every value as an escaped React text node and
// the raw preview puts the serialized markdown in a readonly <textarea> value
// — never dangerouslySetInnerHTML. A <script> or HTML payload in report data is
// therefore inert in both views (asserted in ReportsTab.test.jsx).
// ─────────────────────────────────────────────────────────────────────────

export const PROFILES = {
  full: {
    label: 'Full IR Report',
    description:
      'Comprehensive incident response report containing all approved findings, timeline events, IOCs, MITRE ATT&CK mappings, evidence manifest, and open tasks.',
  },
  executive: {
    label: 'Executive Briefing',
    description:
      'Non-technical management briefing (1-2 pages) summarizing the incident situation, business impact, current status, and high-priority action items.',
  },
  timeline: {
    label: 'Timeline Narrative',
    description:
      'Event-focused chronological narrative report. Ideal for detailing the exact lifecycle and steps of the intrusion.',
  },
  ioc: {
    label: 'Indicators of Compromise (IOC)',
    description:
      'Structured threat intelligence export mapping IOCs to categories, hosts, and source findings.',
  },
  findings: {
    label: 'Findings Detail',
    description:
      'Deep-dive technical report containing full detailed write-ups, observations, and interpretations of every approved finding.',
  },
  status: {
    label: 'Status Summary',
    description:
      'Quick snapshot for standups and daily status checks, containing KPI counts and lists of open tasks.',
  },
}

/** Profile label lookup (falls back to the raw profile key). */
export function profileLabel(profile) {
  return PROFILES[profile]?.label || profile
}

/** Human date string ("locale") — empty string for falsy/invalid input. */
export function formatDate(isoStr) {
  if (!isoStr) return ''
  try {
    return new Date(isoStr).toLocaleString()
  } catch {
    return isoStr
  }
}

/** Compact M/D/YYYY HH:MM stamp used in the saved-reports list rows. */
export function formatReportDate(isoStr) {
  if (!isoStr) return ''
  try {
    const d = new Date(isoStr)
    const month = d.getMonth() + 1
    const day = d.getDate()
    const year = d.getFullYear()
    const hours = String(d.getHours()).padStart(2, '0')
    const minutes = String(d.getMinutes()).padStart(2, '0')
    return `${month}/${day}/${year} ${hours}:${minutes}`
  } catch {
    return isoStr
  }
}

/**
 * Saved-report list shaping (legacy parity): the API list is reversed to
 * chronological, a per-profile version counter (v1, v2 …) is assigned in that
 * order, then reversed back to newest-first for display.
 */
export function withVersions(list) {
  const chronological = [...(list || [])].reverse()
  const counts = {}
  const mapped = chronological.map((r) => {
    counts[r.profile] = (counts[r.profile] || 0) + 1
    return { ...r, version: `v${counts[r.profile]}` }
  })
  mapped.reverse()
  return mapped
}

/** Title-case a snake_case metric key ("open_findings" → "Open Findings"). */
function prettyKey(k) {
  return k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Flatten the IOC section (record-of-arrays OR array) into table rows. */
export function flattenIocs(data) {
  const rows = []
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    for (const [iocType, items] of Object.entries(data)) {
      if (!Array.isArray(items)) continue
      for (const it of items) {
        if (it && typeof it === 'object') rows.push({ ...it, type: it.type || iocType })
        else if (typeof it === 'string') rows.push({ value: it, type: iocType })
      }
    }
  } else if (Array.isArray(data)) {
    for (const it of data) {
      if (it && typeof it === 'object') rows.push(it)
      else if (typeof it === 'string') rows.push({ value: it })
    }
  }
  return rows
}

/**
 * Client-side markdown serializer for the Raw preview + the .md download proxy.
 * Output is a PLAIN STRING placed in a readonly textarea — never injected as
 * HTML. Mirrors the legacy section mapping exactly (summary / findings /
 * timeline / iocs / mitre_mapping / evidence / todos / json fallback) plus the
 * custody appendix.
 */
export function serializeToMarkdown(report) {
  if (!report) return ''
  const meta = report.report_data?.metadata || {}
  const profileName = (report.profile || 'full').toUpperCase()
  const generatedAt = report.generated_at || ''
  const examiner = report.examiner || 'Unknown'
  const caseName = meta.name || 'Unknown Case'
  const caseId = meta.case_id || 'Unknown ID'

  const md = []
  md.push(`# Forensic Incident Report: ${caseName}`)
  md.push('')
  md.push('## Report Metadata')
  md.push(`- **Case ID**: ${caseId}`)
  md.push(`- **Report Profile**: ${profileName}`)
  md.push(`- **Generated At**: ${formatDate(generatedAt)}`)
  md.push(`- **Examiner**: ${examiner}`)
  md.push('')

  if (report.integrity_warning) {
    md.push('> [!CAUTION]')
    md.push(`> **Evidence Integrity Warning**: ${report.integrity_warning}`)
    md.push('')
  } else if (report.evidence_chain_warning) {
    md.push('> [!WARNING]')
    md.push(`> **Evidence Chain Warning**: ${report.evidence_chain_warning}`)
    md.push('')
  }

  const sections = report.sections || []
  const reportData = report.report_data || {}
  const zg = report.zeltser_guidance || {}

  for (const sec of sections) {
    const name = sec.name || 'Section'
    const dataKey = sec.data_key
    md.push(`## ${name}`)
    md.push('')

    if (!dataKey) {
      const guidance = zg[name]
      if (guidance && Array.isArray(guidance.instructions)) {
        md.push('### Guidance & Instructions')
        for (const ins of guidance.instructions) md.push(`- ${ins}`)
        md.push('')
      }
      const matchingHr = (report.human_review_required || []).find((hr) => hr.section === name)
      if (matchingHr) {
        md.push('> [!IMPORTANT]')
        md.push(`> **Human Curation Required**: ${matchingHr.reason}`)
        md.push(`> ${matchingHr.prompt}`)
        md.push('')
      } else {
        md.push(`[Draft Section: Write narrative for ${name} here]`)
        md.push('')
      }
      continue
    }

    const data = reportData[dataKey]
    if (data === undefined || data === null) {
      if (reportData[`${dataKey}_count`] !== undefined) {
        md.push(`Total count of ${dataKey}: **${reportData[`${dataKey}_count`]}**`)
        md.push('')
      } else {
        md.push('*No data available for this section.*')
        md.push('')
      }
      continue
    }

    serializeSection(md, dataKey, data, prettyKey)
  }

  serializeAppendix(md, report.custody_appendix)
  return md.join('\n')
}

/** Serialize one keyed data section into the markdown buffer (legacy parity). */
function serializeSection(md, dataKey, data, pretty) {
  if (dataKey === 'summary') {
    md.push('| Metric | Count |')
    md.push('|---|---|')
    for (const [k, v] of Object.entries(data)) {
      if (typeof v === 'number') md.push(`| ${pretty(k)} | ${v} |`)
    }
    md.push('')
  } else if (dataKey === 'findings') {
    if (!Array.isArray(data) || data.length === 0) {
      md.push('*No approved findings in this report.*')
      md.push('')
    } else {
      for (const f of data) {
        md.push(`### Finding ${f.id || 'N/A'}: ${f.title || 'Untitled'}`)
        md.push(`- **Type**: ${f.type || 'N/A'}`)
        md.push(`- **Confidence**: ${f.confidence || 'N/A'}`)
        md.push(`- **Host**: ${f.host || 'N/A'}`)
        md.push(`- **Affected Account**: ${f.affected_account || 'N/A'}`)
        md.push(`- **Event Timestamp**: ${f.event_timestamp || f.timestamp || 'N/A'}`)
        if (f.tags && f.tags.length > 0) md.push(`- **Tags**: ${f.tags.join(', ')}`)
        md.push('')
        if (f.observation) {
          md.push('#### Observation')
          md.push(String(f.observation))
          md.push('')
        }
        if (f.interpretation) {
          md.push('#### Interpretation')
          md.push(String(f.interpretation))
          md.push('')
        }
      }
    }
  } else if (dataKey === 'timeline') {
    if (!Array.isArray(data) || data.length === 0) {
      md.push('*No timeline events included.*')
      md.push('')
    } else {
      md.push('| Timestamp | Host | Type | Description |')
      md.push('|---|---|---|---|')
      for (const t of data) {
        md.push(
          `| ${t.timestamp || 'N/A'} | ${t.host || 'N/A'} | ${t.type || 'N/A'} | ${t.description || 'No description'} |`,
        )
      }
      md.push('')
    }
  } else if (dataKey === 'iocs') {
    const rows = flattenIocs(data)
    if (rows.length === 0) {
      md.push('*No indicators of compromise.*')
      md.push('')
    } else {
      md.push('| Value | Type | Category | Host | Source Findings |')
      md.push('|---|---|---|---|---|')
      for (const i of rows) {
        md.push(
          `| ${i.value || 'N/A'} | ${i.type || 'N/A'} | ${i.category || 'N/A'} | ${i.host || 'N/A'} | ${(i.source_findings || []).join(', ')} |`,
        )
      }
      md.push('')
    }
  } else if (dataKey === 'mitre_mapping') {
    const keys = Object.keys(data)
    if (keys.length === 0) {
      md.push('*No MITRE ATT&CK mapping.*')
      md.push('')
    } else {
      md.push('| Technique ID | Technique Name | Findings |')
      md.push('|---|---|---|')
      for (const [techId, techInfo] of Object.entries(data)) {
        md.push(
          `| ${techId} | ${techInfo.name || 'Unknown Technique'} | ${(techInfo.findings || []).join(', ')} |`,
        )
      }
      md.push('')
    }
  } else if (dataKey === 'evidence') {
    if (!Array.isArray(data) || data.length === 0) {
      md.push('*No evidence files registered.*')
      md.push('')
    } else {
      md.push('| Path | Size (Bytes) | Hash | Status |')
      md.push('|---|---|---|---|')
      for (const ev of data) {
        md.push(`| ${ev.path || 'N/A'} | ${ev.size_bytes || 0} | \`${ev.sha256 || 'N/A'}\` | ${ev.status || 'N/A'} |`)
      }
      md.push('')
    }
  } else if (dataKey === 'todos') {
    if (!Array.isArray(data) || data.length === 0) {
      md.push('*No open TODOs.*')
      md.push('')
    } else {
      for (const t of data) {
        md.push(`- **${t.title || 'Untitled'}** (Priority: ${t.priority || 'N/A'}, Assigned: ${t.examiner || 'N/A'})`)
        md.push(`  ${t.description || 'No description'}`)
      }
      md.push('')
    }
  } else {
    md.push('```json')
    md.push(JSON.stringify(data, null, 2))
    md.push('```')
    md.push('')
  }
}

/** Serialize the custody / provenance appendix (F-MVP-4) into markdown. */
function serializeAppendix(md, appendix) {
  if (!appendix) return
  md.push('## Appendix: Custody & Provenance')
  md.push('')
  if (appendix.verification_note) {
    md.push(appendix.verification_note)
    md.push('')
  }
  if (appendix.authorized_by_reauth_event) {
    md.push(`- **Authorized by re-auth event**: \`${appendix.authorized_by_reauth_event}\``)
    md.push('')
  }
  const seal = appendix.evidence_seal || {}
  md.push('### Evidence Seal & Hash-Chain Proof')
  md.push('| Field | Value |')
  md.push('|---|---|')
  md.push(`| Seal Status | ${seal.seal_status || 'N/A'} |`)
  md.push(`| Manifest Version | ${seal.manifest_version || 0} |`)
  md.push(`| Manifest Hash | \`${seal.manifest_hash || 'N/A'}\` |`)
  md.push(`| Chain Head Hash | \`${seal.chain_head_hash || 'N/A'}\` |`)
  md.push(`| Ledger Tip Hash | \`${seal.ledger_tip_hash || 'N/A'}\` |`)
  md.push(`| Active Evidence Count | ${seal.active_count || 0} |`)
  md.push('')
  md.push('### Finding Provenance')
  const fp = appendix.finding_provenance || []
  if (fp.length === 0) {
    md.push('*No approved findings.*')
    md.push('')
  } else {
    md.push('| Finding ID | Approval Hash | Approved By | Provenance / Audit Refs |')
    md.push('|---|---|---|---|')
    for (const entry of fp) {
      const refs = (entry.provenance_refs || []).join(', ') || '—'
      md.push(`| ${entry.id || 'N/A'} | \`${entry.content_hash || 'N/A'}\` | ${entry.approved_by || 'N/A'} | ${refs} |`)
    }
    md.push('')
  }
}
