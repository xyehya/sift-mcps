// ─────────────────────────────────────────────────────────────────────────
// Reports — markdown serialization for one keyed data section (split from
// report-markdown.js to keep each utils file <=200 lines, AGENTS §7). Pure:
// pushes plain markdown strings onto the buffer. Mirrors the legacy section
// mapping exactly (summary / findings / timeline / iocs / mitre_mapping /
// evidence / todos / json fallback). Output is never injected as HTML.
// ─────────────────────────────────────────────────────────────────────────

import { flattenIocs } from './reports-utils'

/** Serialize one keyed data section into the markdown buffer (legacy parity). */
export function serializeSection(md, dataKey, data, pretty) {
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

