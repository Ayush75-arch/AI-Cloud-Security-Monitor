import { RiskRing } from '../ui'
import type { DashboardStats } from '../../types'
import { formatDistanceToNow } from 'date-fns'

interface Props { stats: DashboardStats }

export function StatCards({ stats }: Props) {
  const { severity_breakdown: s } = stats

  const cards = [
    {
      label: 'Total Findings',
      value: stats.total_findings,
      sub: `${stats.open_findings} open`,
      accent: '#e8edf2',
    },
    {
      label: 'Critical',
      value: s.critical,
      sub: 'immediate action',
      accent: '#ff3b5c',
    },
    {
      label: 'High',
      value: s.high,
      sub: 'high priority',
      accent: '#ff8c00',
    },
    {
      label: 'Medium',
      value: s.medium,
      sub: 'planned remediation',
      accent: '#ffcc00',
    },
    {
      label: 'Low',
      value: s.low,
      sub: 'informational',
      accent: '#00aaff',
    },
    {
      label: 'Cloud Assets',
      value: stats.total_assets,
      sub: 'scanned resources',
      accent: '#e8edf2',
    },
  ]

  return (
    <div className="grid grid-cols-3 lg:grid-cols-6 border-b border-bg-border">
      {cards.map((c, i) => (
        <div
          key={c.label}
          className="px-5 py-4 border-r border-bg-border last:border-r-0 animate-slide-up"
          style={{ animationDelay: `${i * 50}ms`, animationFillMode: 'both' }}
        >
          <div className="label mb-2">{c.label}</div>
          <div
            className="font-display text-2xl font-bold tabular-nums"
            style={{ color: c.accent }}
          >
            {c.value.toLocaleString()}
          </div>
          <div className="font-mono text-2xs text-text-muted mt-1">{c.sub}</div>
        </div>
      ))}
    </div>
  )
}

export function RiskPanel({ stats }: Props) {
  const lastScan = stats.last_scan_at
    ? formatDistanceToNow(new Date(stats.last_scan_at), { addSuffix: true })
    : 'Never'

  return (
    <div className="panel flex items-center gap-6 px-6 py-4 border-b border-bg-border">
      <RiskRing score={stats.risk_score} />
      <div>
        <div className="label mb-1">Risk Score</div>
        <div className="font-mono text-xs text-text-secondary">
          Last scan: <span className="text-accent-green">{lastScan}</span>
        </div>
      </div>
      <div className="flex gap-6 ml-auto">
        {Object.entries(stats.compliance_scores).map(([fw, score]) => (
          <div key={fw} className="text-center">
            <div className="label mb-1">{fw}</div>
            <div
              className="font-display text-lg font-bold"
              style={{ color: score >= 80 ? '#00ff88' : score >= 60 ? '#ffcc00' : '#ff3b5c' }}
            >
              {score.toFixed(0)}%
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
