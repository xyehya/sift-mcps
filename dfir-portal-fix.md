DFIR Portal — Actionable Fix List for Coding Agent
Each item follows the format: ID · Issue · Fix · Expected Outcome

BUGS (Must Fix — Broken Behaviour)

BUG-001
Issue: The Reports page form has a duplicated label reading "Profile Profile" above the report type dropdown.
Fix: In the Reports view template, find the label element above the dropdown (which selects between "Full IR Report" / "Executive Briefing"). Change the label text from Profile Profile to Report Profile or simply Report Type.
Outcome: Label reads correctly once; no duplicated word visible on the Reports page.

BUG-002
Issue: In the IOC table, the last row (G:\\My Drive\\STARK-RESEARCH-LABS FOLDER\…) renders the HOSTS cell as plain lowercase text srl-forge with no chip/badge styling, while all other rows render SRL-FORGE inside a dark teal rounded chip.
Fix: The host chip component is apparently not rendering when the host string is lowercase. Normalize all host values to uppercase before rendering, and ensure the chip component wraps the value regardless of its case. The root cause is likely a case-sensitive string match in the chip renderer — remove that condition or add .toUpperCase() on the value before comparison.
Outcome: Every row in the IOC table renders the host value inside the same styled dark-teal chip. No plain-text host values anywhere in the table.

BUG-003
Issue: The RECENT ACTIVITY widget on the Overview page shows "No findings in this period" when Last 24h is the active filter, even though 25 findings exist in the case and work was done recently.
Fix: Audit the query that powers the Recent Activity widget. Confirm whether it filters on created_at or updated_at. If it only tracks newly created findings and the findings were created more than 24h ago, change the filter to also include findings with updated_at or reviewed_at within the window. Alternatively expose a clear label clarifying what "activity" means (e.g. "No findings created in this period").
Outcome: The widget either correctly shows recent activity, or clearly communicates what "activity" means so the empty state is not confusing.

BUG-004
Issue: The Finding ID in the Findings sidebar wraps across three lines: F– / claude– / 001, breaking layout and readability.
Fix: Apply white-space: nowrap and overflow: hidden with text-overflow: ellipsis to the finding ID element in the sidebar list item. The ID column should be treated as a fixed-width monospace token, not flowing prose. If the column is too narrow, increase the left panel minimum width by ~20px or reduce the title column's minimum font size.
Outcome: Every finding ID (F-claude-001, F-lms-008, etc.) renders on a single line, never wrapping.

BUG-005
Issue: The [] brackets appear next to every timestamp in the Timeline view with no label, tooltip, or explanation. They appear to be empty tag/evidence containers but are completely opaque to users.
Fix: If [] represents attached evidence tags (empty when no evidence is linked), replace the empty brackets with either nothing (hide when empty) or a small muted icon with a tooltip that says "No evidence tags attached." If they are intentional interactive elements, give them a visible affordance such as a + icon and a tooltip.
Outcome: No unexplained [] symbols visible in the Timeline. Each timeline row either shows evidence tags with clear labelling or shows nothing in that position.

COLOR & VISUAL CONSISTENCY

CLR-001
Issue: PENDING and STAGED stat cards on the Overview both use the same orange color for their numbers (25 and 0), making them visually indistinguishable despite being different workflow states.
Fix: Assign STAGED a distinct color — a neutral cool gray or a soft blue (e.g. #8b9dc3) — since staged items are not yet in the review pipeline. Keep PENDING in amber/orange as a signal of "needs attention." Update the color token for the STAGED counter specifically.
Outcome: The four Overview stat cards each use a meaningfully distinct color: FINDINGS = cyan, APPROVED = green, PENDING = amber, STAGED = muted gray/blue.

CLR-002
Issue: In the Findings detail header, HIGH, FINDING, and DRAFT are all rendered in the same muted unstyled gray text with no color differentiation, making severity indistinguishable from type and status at a glance.
Fix: Apply semantic color tokens to each tag type in the finding header: HIGH → red/coral (same red used in the severity bar chart, e.g. #ff4d6d); FINDING → a neutral teal or white pill to indicate type; DRAFT → amber/orange to indicate pending review state. These should be small labeled chips, not plain text.
Outcome: The finding detail header's tag row clearly communicates severity (red), type (neutral), and status (amber) at a glance without reading the text.

CLR-003
Issue: APPROVED text in the IOC table renders in a brighter green than 1 APPROVED in the Hosts table and Accounts table — same semantic value, different visual treatment across views.
Fix: Define a single shared CSS token / design token for the "approved" state color (e.g. --status-approved: #22c55e) and apply it universally to every APPROVED status label across all tables (IOC, Hosts, Accounts, Findings sidebar).
Outcome: The word APPROVED in green looks identical in every table and every view throughout the app.

CLR-004
Issue: MITRE ATT&CK technique tags on the Overview all render in identical cyan outlined chips with no distinction between parent techniques (T1078) and sub-techniques (T1078.001). T1078 and T1078.001 appear side by side as visual equals.
Fix: Sub-techniques (those containing a .) should render with a slightly indented position or a visually lighter style — e.g. a filled chip at reduced opacity vs. the parent's full-opacity outlined chip. Alternatively, group parent + children and add a subtle left-border indent. At minimum, use a dimmer text color for sub-technique IDs.
Outcome: A user can immediately distinguish parent MITRE techniques from sub-techniques in the tag cloud without reading the ID format.

CLR-005
Issue: The GRADE: PARTIAL badge on findings uses an amber outline, but there is no consistent badge system across findings — some findings may have different grades with no legend visible anywhere.
Fix: Define a 3-or-4 tier grade badge system with explicit colors: GRADE: FULL = green outline, GRADE: PARTIAL = amber outline, GRADE: UNGRADED = muted gray outline. Add a small ? icon next to the badge that shows a tooltip: "Grade reflects completeness of evidence support. Partial = some evidence missing." Apply this badge definition consistently across all finding detail views.
Outcome: Every finding shows a consistently colored grade badge, and any examiner can understand the grading scale without external documentation.

TYPOGRAPHY & CASING

TYP-001
Issue: Section header casing is inconsistent across the entire app. Some headers are ALL CAPS (SEVERITY DISTRIBUTION, WRITE BLOCK STATUS, GENERATE REPORT, AGENT ID), others are Title Case (Evidence Chain, Indicators of Compromise, Hosts in Scope, Examiner Context Notes).
Fix: Standardize all section-level headers to Title Case (e.g. "Severity Distribution", "Write Block Status", "Generate Report"). Reserve ALL CAPS exclusively for table column headers (e.g. VALUE, TYPE, STATUS) where it is already consistently used. Do a global pass on every <h2>, <h3>, and section label element.
Outcome: All section headers use Title Case. All table column headers use ALL CAPS. No mixing occurs anywhere in the app.

TYP-002
Issue: The examiner username is displayed three times simultaneously on the Findings page: (1) as regular text in the top-right header, (2) inside a rounded EXAMINER role pill next to it, and (3) in the bottom status bar. This is redundant and clutters the chrome.
Fix: In the top-right header, keep only the EXAMINER role pill (or a combined examiner · EXAMINER single chip). Remove the standalone plain-text examiner that appears immediately to the left of the pill — the pill already communicates both identity and role. In the bottom status bar, remove examiner entirely — sync status and case seal state are sufficient there.
Outcome: The username appears exactly once in the persistent UI chrome, inside the role chip in the top-right header.

TYP-003
Issue: The Full report type in the Overview's Reports card and the Reports page list displays cryptographic hashes (9a29853e, 6985c7e9, 8b633bc3) as the only differentiator between report versions. These are meaningless to a human reader.
Fix: Display a human-readable version label: the full datetime of generation (already available as 5/28/2026) plus the time component, or a sequential version number (v1, v2). The hash can remain but should be truncated and placed in a secondary muted style or shown only on hover as a tooltip. Example: Full IR Report — v2 · 5/28/2026 14:32.
Outcome: Users can distinguish between two "Full IR Report" entries without decoding a hash. The hash remains accessible for integrity purposes but is not the primary identifier.

UI COHERENCE & CONSISTENCY

COH-001
Issue: The two collapsible sections in the Findings detail pane use inconsistent expand affordances: "Examiner Context Notes" has ▶ on the left, while "Evidence & Context (Collapsible Details)" has ▶ on the right.
Fix: Standardize all collapsible/accordion sections to use ▶ (collapsed) and ▼ (expanded) on the left side of the label. This is the universal convention. Update the second collapsible's template to move the arrow to the left.
Outcome: All collapsible sections in the app expand and collapse consistently with the arrow on the left side.

COH-002
Issue: The Timeline filter pills (Auth, Execution, Process, File, Network, Persistence, Registry, Lateral, Other) show no visible active/selected state. After clicking, the pill appearance does not change, making it impossible to know which filter is active.
Fix: Add a distinct active state style to the filter pill component: filled background (e.g. teal fill with dark text) when selected, outlined when unselected. This is a standard toggle-pill pattern. Ensure the active state is applied to the button's CSS class on click and persists until deselected.
Outcome: Any active Timeline filter pill is clearly distinguishable (filled) from inactive ones (outlined). A user can see at a glance which category filters are applied.

COH-003
Issue: The SRL-FORGE host chip in the IOC and Accounts tables is a dark teal rounded chip everywhere, but in the Timeline the same host appears as plain text within the line content with no chip. These are the same entity displayed inconsistently.
Fix: The Timeline does not have a dedicated host column (by design), so this is acceptable. However, if the host name appears inline in event descriptions (SRL-FORGE), wrap those instances in the same teal host chip component used in other tables for visual recognition. Apply this as a text-node substitution in the Timeline event description renderer.
Outcome: SRL-FORGE as an entity is visually identifiable with its chip style whenever it appears, whether in a table or inline text.

COH-004
Issue: The Finding ID naming prefix is inconsistent with no explanation: some IDs begin with F-claude- and others with F-lms-. Users have no way to understand that these prefixes represent different AI agent sources (Claude vs. LMStudio).
Fix: Add a small ℹ info icon next to the Finding ID in both the sidebar list items and the detail header. On hover, show a tooltip: "F-claude-NNN = Finding created by Claude agent. F-lms-NNN = Finding created by LMStudio agent." Long-term, consider a small colored source-agent badge (e.g. a 2-letter pill: CL or LM) next to the ID.
Outcome: Any examiner can immediately understand the provenance of a finding from its ID without prior system knowledge.

COH-005
Issue: The HOSTED column in Accounts and IOC tables repeats SRL-FORGE on every single row (24+ times) because there is only one host in scope. This wastes horizontal space and adds visual noise.
Fix: When a case has only one host in scope, suppress the repetitive host chip in the table body and instead display the host once in the table's section header as context: e.g. "Indicators of Compromise (24 of 24) — Host: SRL-FORGE". When multiple hosts exist, restore the per-row column display. This is a conditional rendering decision based on hosts.length === 1.
Outcome: In single-host cases, the host column is replaced by a single header-level annotation, removing dozens of identical repeated chips from the table.

COH-006
Issue: The Settings page lists hermes-default twice as two separate active agent token entries (both labeled "Installer-created Hermes service token" with "Never" expiry). This appears to be duplicate data that could confuse administrators.
Fix: Investigate whether this is intentional (two separate tokens for the same agent) or a data duplication bug. If intentional, differentiate them with a sequential index or creation timestamp in the Label column. If a bug, deduplicate at the data layer and show only one entry.
Outcome: No two rows in the Active Agent Tokens table are visually identical. Each row is uniquely identifiable.

EMPTY STATES & INFORMATION CLARITY

EMP-001
Issue: The TODOs page, Evidence registered files section, and Hosts page (single row) all show large empty dark voids below sparse content, making the UI look broken or unfinished.
Fix: For each empty or near-empty view, add a contextually helpful empty state: an icon, a short explanation, and a call-to-action where applicable. Example for TODOs: a checklist icon + "No TODOs yet. Create one to track investigation tasks." For Evidence: a file icon + "No evidence files registered. Use the Rescan button or add files to the evidence directory." These states should be vertically centered in their container.
Outcome: Every view with no data shows a purposeful, informative empty state rather than a blank dark void.

EMP-002
Issue: The Evidence Chain page's "Solana Anchor Status" panel contains the message: "⊠ Solana anchoring not configured. Set AGENTIR_SOLANA_KEYPAIR in the gateway environment..." The ⊠ character is an encoding artifact (likely a broken Unicode symbol) and the message exposes a raw environment variable name without any contextual help link.
Fix: Replace ⊠ with a proper warning icon (e.g. ⚠ or an SVG icon consistent with the rest of the UI). Add a small "Learn more" or "Setup guide" link next to the message that points to documentation. The environment variable name AGENTIR_SOLANA_KEYPAIR should be styled in a <code> monospace inline element to visually distinguish it as a technical token.
Outcome: The Solana status message displays a clean warning icon, a readable message, and a styled inline code token — no broken characters.

EMP-003
Issue: The Write Protection Warning on the Evidence page renders the same information twice: once as styled bold text ("Evidence directory is NOT write-protected...") and then immediately again in a code block with the exact same content but in monospace. This is direct content duplication.
Fix: Remove the duplicate. Keep the human-readable styled warning text above. Replace the code block with a single actionable line showing the recommended mount command: e.g. mount -o ro,noatime /dev/sdX /mnt/evidence. The code block should contain the command, not a restatement of the prose warning.
Outcome: The Write Protection Warning card contains one concise human-readable warning sentence and one actionable code command — no repeated prose.

NAVIGATION & CHROME

NAV-001
Issue: The bottom status bar contains four items in one line: ● SEALED ✓ · no staged changes · sync less than a minute ago · examiner. This bar is overloaded and examiner is the third or fourth redundant appearance of the username in a single view.
Fix: Reduce the status bar to three elements maximum: [seal status] · [sync status] · [case ID or session indicator]. Remove the examiner username from the status bar entirely — it is already in the top-right header. Optionally replace the raw text with iconographic status indicators (lock icon for SEALED, sync icon for sync time) to save space.
Outcome: The status bar is clean, non-redundant, and contains only system-state information relevant to the active session.

NAV-002
Issue: The ● idle indicator in the top-right header uses a gray dot with the text "idle." It is unclear what system is idle, what the alternative states are, or whether this requires user attention.
Fix: Add a tooltip on hover to the idle indicator: e.g. "Agent status: idle — No AI analysis tasks running." Define and document the other possible states (e.g. processing, error) with distinct dot colors: gray = idle, yellow = processing, red = error. Apply those colors to the dot component.
Outcome: A user hovering the ● idle indicator understands what it means. The dot color alone communicates the system state at a glance.

NAV-003
Issue: The case selector in the top header bar (rocba-drive-20260526-1417 ▾) is the only way to switch cases, but it looks like a static label rather than an interactive dropdown due to low visual affordance. The dropdown arrow ▾ is very small and low-contrast.
Fix: Style the case selector as an explicit interactive control: add a visible rounded border or subtle background fill on hover, increase the dropdown arrow size slightly, and ensure the cursor changes to pointer on hover. This communicates that it is a clickable case-switching control, not a read-only label.
Outcome: Users immediately recognize the case selector as an interactive dropdown, not a static title.

Total action items: 21 — 5 bugs, 5 color fixes, 3 typography fixes, 6 coherence fixes, 3 empty state / clarity fixes, 3 navigation fixes.
Priority order for the coding agent: BUG-001 → BUG-002 → BUG-004 → TYP-001 → CLR-001 → CLR-002 → COH-001 → COH-002 → COH-005 → TYP-002 → then remainder.