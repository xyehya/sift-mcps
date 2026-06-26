import { FolderSearch } from 'lucide-react'

import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// UnregisteredFiles — detected-but-unsealed files table (legacy IA parity §5).
// Renders only when there are unregistered files. Each row: Path · Source-notes
// input · Description input (both bound to unregisteredMetadata[path]) · per-row
// Ignore / Delete. Header has "Seal Manifest (N file/s)" → opens the seal modal.
// ─────────────────────────────────────────────────────────────────────────

export function UnregisteredFiles({
  chainStatus,
  unregisteredMetadata,
  onMetaChange,
  onIgnore,
  onDelete,
  onSeal,
}) {
  const unregistered = chainStatus?.unregistered ?? []
  if (!unregistered.length) return null

  return (
    <div className="space-y-3 rounded-lg border border-status-pending/30 bg-status-pending/5 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="flex items-center gap-1.5 text-xs font-bold text-foreground">
          <FolderSearch className="size-3.5" aria-hidden />
          Unregistered Evidence Files Detected
        </h4>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onSeal}
          className="mono text-xs font-semibold text-status-pending border-status-pending/40 hover:bg-status-pending/10"
        >
          Seal Manifest ({unregistered.length} file{unregistered.length === 1 ? '' : 's'})
        </Button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border-soft text-muted-foreground">
              <th className="w-1/3 py-2 pr-4 font-semibold">Path</th>
              <th className="w-1/3 py-2 pr-4 font-semibold">Source Notes</th>
              <th className="w-1/3 py-2 pr-4 font-semibold">Description</th>
              <th className="py-2 text-right font-semibold">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-faint">
            {unregistered.map((path) => (
              <tr key={path} className="text-foreground">
                <td className="mono break-all py-2 pr-4">{path}</td>
                <td className="py-2 pr-4">
                  <input
                    type="text"
                    value={unregisteredMetadata[path]?.source ?? ''}
                    onChange={(e) => onMetaChange(path, 'source', e.target.value)}
                    placeholder="e.g. USB drive #1"
                    className="w-full rounded border border-border-soft bg-bg-raised px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>
                <td className="py-2 pr-4">
                  <input
                    type="text"
                    value={unregisteredMetadata[path]?.description ?? ''}
                    onChange={(e) => onMetaChange(path, 'description', e.target.value)}
                    placeholder="e.g. Acquired disk image"
                    className="w-full rounded border border-border-soft bg-bg-raised px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>
                <td className="whitespace-nowrap py-2 text-right">
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => onIgnore(path)}
                    className="mono mr-2 text-[10px] text-muted-foreground hover:text-foreground hover:border-border-hard"
                  >
                    Ignore
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => onDelete(path)}
                    className="mono text-[10px] text-muted-foreground hover:text-destructive hover:border-destructive"
                    title="Permanently delete this file's bytes from the evidence directory"
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
