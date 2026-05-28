export function Skeleton({ className = '', style = {} }) {
  return <div className={`skeleton ${className}`} style={{ height: 14, ...style }} />
}

export function SkeletonBlock({ rows = 3, gap = 8 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap }}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} style={{ width: i % 3 === 2 ? '60%' : '100%', height: 12 }} />
      ))}
    </div>
  )
}
