import clsx from 'clsx'
import type { Severity, ScanStatus } from '../../types'

// ── Severity Badge ────────────────────────────────────────────────────────────

const SEVERITY_CLASSES: Record<Severity, string> = {
  critical: 'badge-critical',
  high:     'bg-orange-950 text-orange-400 border border-orange-800',
  medium:   'badge-medium',
  low:      'badge-low',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx('font-mono text-2xs uppercase tracking-widest px-2 py-0.5', SEVERITY_CLASSES[severity])}>
      {severity}
    </span>
  )
}

// ── Status Badge ──────────────────────────────────────────────────────────────

const STATUS_CLASSES: Record<ScanStatus, string> = {
  pending:   'text-text-secondary border-bg-border',
  running:   'text-accent-green border-accent-green animate-pulse',
  completed: 'text-accent-green border-accent-muted',
  failed:    'text-accent-red border-red-800',
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={clsx('font-mono text-2xs uppercase tracking-widest px-2 py-0.5 border', STATUS_CLASSES[status])}>
      {status}
    </span>
  )
}

// ── Finding Status Badge ──────────────────────────────────────────────────────

export function FindingStatusBadge({ status }: { status: string }) {
  const cls =
    status === 'open'       ? 'text-accent-green border-accent-muted' :
    status === 'suppressed' ? 'text-text-secondary border-bg-border' :
                              'text-accent-blue border-blue-800'
  return (
    <span className={clsx('font-mono text-2xs uppercase tracking-widest px-2 py-0.5 border', cls)}>
      {status}
    </span>
  )
}

// ── Spinner ───────────────────────────────────────────────────────────────────

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className="animate-spin text-accent-green"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeOpacity="0.2" />
      <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
    </svg>
  )
}

// ── Severity Dot ──────────────────────────────────────────────────────────────

const DOT_COLORS: Record<Severity, string> = {
  critical: 'bg-accent-red',
  high:     'bg-orange-400',
  medium:   'bg-accent-yellow',
  low:      'bg-accent-blue',
}

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span className={clsx('inline-block w-1.5 h-1.5 rounded-full', DOT_COLORS[severity])} />
}

// ── Empty State ───────────────────────────────────────────────────────────────

export function EmptyState({ message = 'No data' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-muted font-mono text-xs uppercase tracking-widest">
      <span className="text-3xl mb-3 opacity-20">⬡</span>
      {message}
    </div>
  )
}

// ── Risk Score Ring ───────────────────────────────────────────────────────────

export function RiskRing({ score }: { score: number }) {
  const r = 28
  const circ = 2 * Math.PI * r
  const filled = ((100 - score) / 100) * circ
  const color = score > 70 ? '#ff3b5c' : score > 40 ? '#ffcc00' : '#00ff88'

  return (
    <svg width="80" height="80" viewBox="0 0 80 80">
      <circle cx="40" cy="40" r={r} stroke="#1e2328" strokeWidth="6" fill="none" />
      <circle
        cx="40" cy="40" r={r}
        stroke={color} strokeWidth="6" fill="none"
        strokeDasharray={circ}
        strokeDashoffset={filled}
        strokeLinecap="square"
        transform="rotate(-90 40 40)"
        style={{ transition: 'stroke-dashoffset 0.8s ease' }}
      />
      <text x="40" y="44" textAnchor="middle" fill={color} fontSize="13" fontFamily="IBM Plex Mono" fontWeight="600">
        {Math.round(score)}
      </text>
    </svg>
  )
}
