// ─────────────────────────────────────────────────────────────────────────
// Reports — pure helpers: report profiles, date formatters, IOC flattening,
// and saved-report versioning. No JSX / no store, so this logic stays
// unit-testable and the component files stay clean. The markdown serializer
// lives in report-markdown.js (split out to keep each utils file <=200 lines).
//
// SECURITY: this module only ever produces PLAIN STRINGS / data. The rendered
// preview (ReportRenderedView) renders every value as an escaped React text
// node — never dangerouslySetInnerHTML — so an HTML payload in report data is
// inert (asserted in ReportsTab.test.jsx).
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

/** Trigger a browser file download for a Blob (revokes the object URL after). */
export function triggerDownload(blob, filename) {
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(objectUrl)
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
