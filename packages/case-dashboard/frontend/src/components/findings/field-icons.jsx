// ─────────────────────────────────────────────────────────────────────────
// Field glyphs for the three FindingDetail sections (Observation · jade /
// Interpretation · amber / Justification & custody · steel). Plain JSX element
// constants — no components, no state — so they live apart from FindingField to
// keep react-refresh happy (a component file must export only components).
// Stroke colors are token vars (no hex).
// ─────────────────────────────────────────────────────────────────────────

export const ObservationIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--jade)" strokeWidth="1.9" aria-hidden className="shrink-0">
    <circle cx="11" cy="11" r="7"/>
    <path d="m20 20-3.5-3.5M8.5 11l1.8 1.8L14 9"/>
  </svg>
)

export const InterpretationIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" strokeWidth="1.9" aria-hidden className="shrink-0">
    <path d="M9 18h6M10 21h4M12 3a6 6 0 0 1 4 10.5c-.7.7-1 1.2-1 2.5H9c0-1.3-.3-1.8-1-2.5A6 6 0 0 1 12 3Z"/>
  </svg>
)

export const CustodyIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--steel)" strokeWidth="1.9" aria-hidden className="shrink-0">
    <path d="M12 3v18M7 7l5-3 5 3M5 11h14M5 11l-2 4a3 3 0 0 0 4 0zM19 11l-2 4a3 3 0 0 0 4 0z"/>
  </svg>
)
