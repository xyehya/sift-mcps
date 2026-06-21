// ─────────────────────────────────────────────────────────────────────────
// Reports — client-side markdown serializer (split from reports-utils to keep
// each utils file <=200 lines, AGENTS §7). Output is ALWAYS a PLAIN STRING that
// the Raw preview binds to a readonly <textarea> value — never injected as HTML
// (no dangerouslySetInnerHTML). A <script>/HTML payload in report data is inert.
// Mirrors the legacy section mapping exactly.
// ─────────────────────────────────────────────────────────────────────────

import { formatDate } from './reports-utils'
import { serializeSection } from './report-markdown-sections'

/** Title-case a snake_case metric key ("open_findings" → "Open Findings"). */
function prettyKey(k) {
  return k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
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
