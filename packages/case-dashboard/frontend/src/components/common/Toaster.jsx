import { useStoreSlice } from '../../store/useStore'

const TYPE_COLORS = {
  info:    'var(--cyan)',
  success: 'var(--jade)',
  warn:    'var(--amber)',
  error:   'var(--crimson)',
}

export function Toaster() {
  const { toasts, dismissToast } = useStoreSlice((state) => ({
    toasts: state.toasts,
    dismissToast: state.dismissToast,
  }))
  return (
    <div className="fixed bottom-10 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map((t) => (
        <div key={t.id}
          className="pointer-events-auto flex items-center gap-2 px-4 py-2.5 rounded text-xs font-sans shadow-lg"
          style={{
            background: 'var(--bg-overlay)',
            border: `1px solid ${TYPE_COLORS[t.type] ?? TYPE_COLORS.info}`,
            color: 'var(--text-primary)',
            maxWidth: 320,
          }}
          onClick={() => dismissToast(t.id)}
        >
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: TYPE_COLORS[t.type] ?? TYPE_COLORS.info }} />
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
