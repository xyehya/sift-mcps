import { flattenIocs } from './reports-utils'

// ─────────────────────────────────────────────────────────────────────────
// ReportSection — renders one report section's body (legacy parity §10). Every
// keyed data section (summary / findings / timeline / iocs / mitre_mapping /
// evidence / todos / json fallback) plus the narrative/guidance placeholder.
//
// SECURITY: every report value is rendered as an escaped React text node (JSX
// children) or as a readonly textarea value upstream — NEVER via
// dangerouslySetInnerHTML. A <script>/HTML payload in any field renders inert.
// ─────────────────────────────────────────────────────────────────────────

const TH = 'mono px-2 py-1.5 text-left text-[10px] font-bold text-muted-foreground'
const TABLE = 'min-w-full overflow-hidden rounded-lg border border-border-soft bg-card text-[11px] font-mono'
const ROW = 'border-b border-border-faint last:border-0 hover:bg-bg-raised/40'

function prettyKey(k) {
  return k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function NarrativeSection({ name, zg, humanReview }) {
  const hr = (humanReview || []).find((h) => h.section === name)
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border-soft bg-card p-4">
      {zg && Array.isArray(zg.instructions) && (
        <div className="flex flex-col gap-1 border-b border-border-faint pb-2 text-[11px] text-muted-foreground">
          <span className="mono font-bold uppercase tracking-wider text-muted-foreground">
            Zeltser IR Guidance:
          </span>
          <ul className="mt-1 flex list-disc flex-col gap-1 pl-4">
            {zg.instructions.map((ins, i) => (
              <li key={i}>{ins}</li>
            ))}
          </ul>
        </div>
      )}
      {hr ? (
        <div className="flex flex-col gap-1 rounded-lg border border-status-pending/20 bg-amber-dim p-3">
          <span className="mono text-[11px] font-bold uppercase text-status-pending">
            Human Curation Required ({hr.reason})
          </span>
          <p className="mt-0.5 text-xs italic text-foreground">{hr.prompt}</p>
        </div>
      ) : (
        <p className="mono text-xs italic text-muted-foreground">
          [Narrative segment draft placeholder. examiner notes will append here.]
        </p>
      )}
    </div>
  )
}

function SummaryTable({ data }) {
  return (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-border-soft bg-bg-raised">
          <th className={TH}>Metric Key</th>
          <th className={TH}>Count</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(data).map(
          ([k, v]) =>
            typeof v === 'number' && (
              <tr key={k} className={ROW}>
                <td className="px-2 py-1.5 font-bold text-foreground">{prettyKey(k)}</td>
                <td className="px-2 py-1.5 font-bold text-primary">{v}</td>
              </tr>
            ),
        )}
      </tbody>
    </table>
  )
}

function FindingsBlock({ data }) {
  if (!Array.isArray(data) || data.length === 0) {
    return <span className="text-xs italic text-muted-foreground">No approved findings.</span>
  }
  return (
    <div className="flex flex-col gap-4">
      {data.map((f, i) => (
        <div key={i} className="flex flex-col gap-2 rounded-lg border border-border-soft bg-card p-4">
          <div className="flex items-center justify-between border-b border-border-faint pb-1.5">
            <span className="text-sm font-bold text-foreground">
              {f.id}: {f.title}
            </span>
            <span className="mono rounded border border-border-soft bg-bg-raised px-1.5 py-0.5 text-[10px] font-bold text-primary">
              {f.confidence} Confidence
            </span>
          </div>
          <div className="mono grid grid-cols-3 gap-2 text-[10px] text-muted-foreground">
            <div>
              Host: <span className="font-bold text-foreground">{f.host || 'N/A'}</span>
            </div>
            <div>
              Account: <span className="font-bold text-foreground">{f.affected_account || 'N/A'}</span>
            </div>
            <div>
              Timestamp:{' '}
              <span className="font-bold text-foreground">{f.event_timestamp || f.timestamp || 'N/A'}</span>
            </div>
          </div>
          {f.observation && (
            <div className="mt-2 text-xs">
              <span className="mono block text-[10px] font-bold uppercase text-muted-foreground">Observation:</span>
              <p className="mt-0.5 text-foreground">{f.observation}</p>
            </div>
          )}
          {f.interpretation && (
            <div className="mt-2 text-xs">
              <span className="mono block text-[10px] font-bold uppercase text-muted-foreground">
                Interpretation:
              </span>
              <p className="mt-0.5 text-foreground">{f.interpretation}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function TimelineTable({ data }) {
  if (!Array.isArray(data) || data.length === 0) {
    return <span className="text-xs italic text-muted-foreground">No timeline data.</span>
  }
  return (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-border-soft bg-bg-raised">
          <th className={`${TH} w-1/4`}>Timestamp</th>
          <th className={`${TH} w-1/6`}>Host</th>
          <th className={`${TH} w-1/6`}>Type</th>
          <th className={TH}>Description</th>
        </tr>
      </thead>
      <tbody>
        {data.map((t, i) => (
          <tr key={i} className={ROW}>
            <td className="px-2 py-1.5 text-muted-foreground">{t.timestamp}</td>
            <td className="px-2 py-1.5">{t.host}</td>
            <td className="px-2 py-1.5">
              <span className="rounded border border-border-faint bg-bg-raised px-1 py-0.5 text-[9px] text-muted-foreground">
                {t.type}
              </span>
            </td>
            <td className="px-2 py-1.5 text-foreground">{t.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function IocsTable({ data }) {
  const rows = flattenIocs(data)
  if (rows.length === 0) return <span className="text-xs italic text-muted-foreground">No IOCs.</span>
  return (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-border-soft bg-bg-raised">
          <th className={`${TH} w-1/3`}>Value</th>
          <th className={TH}>Type</th>
          <th className={TH}>Category</th>
          <th className={TH}>Host</th>
          <th className={TH}>Sources</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((ioc, i) => (
          <tr key={i} className={ROW}>
            <td className="break-all px-2 py-1.5 font-bold text-primary">{ioc.value}</td>
            <td className="px-2 py-1.5">{ioc.type}</td>
            <td className="px-2 py-1.5">{ioc.category}</td>
            <td className="px-2 py-1.5 text-muted-foreground">{ioc.host}</td>
            <td className="px-2 py-1.5 text-muted-foreground">{(ioc.source_findings || []).join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function MitreTable({ data }) {
  if (Object.keys(data).length === 0) {
    return <span className="text-xs italic text-muted-foreground">No MITRE ATT&CK mapping.</span>
  }
  return (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-border-soft bg-bg-raised">
          <th className={`${TH} w-1/4`}>Technique ID</th>
          <th className={`${TH} w-1/2`}>Name</th>
          <th className={TH}>Findings</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(data).map(([techId, techInfo]) => (
          <tr key={techId} className={ROW}>
            <td className="px-2 py-1.5 font-bold text-primary">{techId}</td>
            <td className="px-2 py-1.5">{techInfo.name}</td>
            <td className="px-2 py-1.5 text-muted-foreground">{(techInfo.findings || []).join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function EvidenceTable({ data }) {
  if (!Array.isArray(data) || data.length === 0) {
    return <span className="text-xs italic text-muted-foreground">No evidence.</span>
  }
  return (
    <table className={TABLE}>
      <thead>
        <tr className="border-b border-border-soft bg-bg-raised">
          <th className={`${TH} w-1/3`}>Path</th>
          <th className={TH}>Size</th>
          <th className={`${TH} w-1/3`}>Hash (SHA-256)</th>
          <th className={TH}>Status</th>
        </tr>
      </thead>
      <tbody>
        {data.map((ev, i) => (
          <tr key={i} className={ROW}>
            <td className="break-all px-2 py-1.5 text-foreground">{ev.path}</td>
            <td className="px-2 py-1.5 text-muted-foreground">{ev.size_bytes}</td>
            <td className="max-w-[150px] select-all truncate px-2 py-1.5 text-muted-foreground" title={ev.sha256}>
              {ev.sha256}
            </td>
            <td className="px-2 py-1.5">
              <span className="rounded border border-border-faint bg-bg-raised px-1 py-0.5 text-[10px] font-bold uppercase">
                {ev.status}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function TodosBlock({ data }) {
  if (!Array.isArray(data) || data.length === 0) {
    return <span className="text-xs italic text-muted-foreground">No open TODOs.</span>
  }
  return (
    <div className="flex flex-col gap-2">
      {data.map((todo, i) => (
        <div key={i} className="flex flex-col gap-1 rounded-lg border border-border-soft bg-card p-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-foreground">{todo.title}</span>
            <span className="mono rounded border border-border-soft bg-bg-raised px-1 text-[9px] uppercase text-primary">
              {todo.priority} priority
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">{todo.description}</p>
          <div className="mono mt-1 text-[9px] text-muted-foreground">Assigned: {todo.examiner}</div>
        </div>
      ))}
    </div>
  )
}

export function ReportSection({ section, reportData, zeltser, humanReview }) {
  const name = section.name || 'Section'
  const dataKey = section.data_key
  const data = reportData?.[dataKey]

  let body
  if (!dataKey) {
    body = <NarrativeSection name={name} zg={zeltser?.[name]} humanReview={humanReview} />
  } else if (data === undefined || data === null) {
    const count = reportData?.[`${dataKey}_count`]
    body =
      count !== undefined ? (
        <div className="mono text-xs text-foreground">
          Total Count: <span className="font-bold text-primary">{count}</span>
        </div>
      ) : (
        <span className="text-xs italic text-muted-foreground">No data available for this section.</span>
      )
  } else if (dataKey === 'summary') body = <SummaryTable data={data} />
  else if (dataKey === 'findings') body = <FindingsBlock data={data} />
  else if (dataKey === 'timeline') body = <TimelineTable data={data} />
  else if (dataKey === 'iocs') body = <IocsTable data={data} />
  else if (dataKey === 'mitre_mapping') body = <MitreTable data={data} />
  else if (dataKey === 'evidence') body = <EvidenceTable data={data} />
  else if (dataKey === 'todos') body = <TodosBlock data={data} />
  else
    body = (
      <pre className="mono overflow-x-auto rounded-lg border border-border-soft bg-card p-3 text-left text-xs">
        {JSON.stringify(data, null, 2)}
      </pre>
    )

  return (
    <div className="flex flex-col gap-3">
      <h2 className="mt-4 border-b border-border-faint pb-1.5 text-lg font-bold text-foreground">{name}</h2>
      {dataKey ? <div className="overflow-x-auto">{body}</div> : body}
    </div>
  )
}
