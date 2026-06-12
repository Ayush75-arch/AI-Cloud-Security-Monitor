import type { ComplianceSummary } from '../../types'
import { RadialBarChart, RadialBar, ResponsiveContainer, Tooltip } from 'recharts'

interface Props { data: ComplianceSummary }

function scoreColor(score: number) {
  if (score >= 80) return '#00ff88'
  if (score >= 60) return '#ffcc00'
  return '#ff3b5c'
}

export function CompliancePanel({ data }: Props) {
  return (
    <div className="panel h-full">
      <div className="panel-header">
        <span className="label">Compliance Posture</span>
        <span className="font-display text-sm font-bold" style={{ color: scoreColor(data.overall_score) }}>
          {data.overall_score.toFixed(0)}% overall
        </span>
      </div>
      <div className="p-4 space-y-4">
        {data.frameworks.map((fw) => {
          const color = scoreColor(fw.score)
          const pct = fw.score / 100
          return (
            <div key={fw.framework}>
              <div className="flex justify-between items-baseline mb-1">
                <span className="font-mono text-xs text-text-secondary uppercase tracking-widest">{fw.framework}</span>
                <span className="font-mono text-xs tabular-nums" style={{ color }}>
                  {fw.score.toFixed(0)}%
                </span>
              </div>
              <div className="h-1 bg-bg-border w-full">
                <div
                  className="h-full transition-all duration-700"
                  style={{ width: `${fw.score}%`, background: color }}
                />
              </div>
              <div className="flex justify-between mt-1">
                <span className="font-mono text-2xs text-text-muted">{fw.passed_controls} passed</span>
                <span className="font-mono text-2xs text-accent-red">{fw.failed_controls} failed</span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function ComplianceControlTable({ data }: Props) {
  const allControls = data.frameworks.flatMap((fw) =>
    Object.entries(fw.control_details).map(([ctrl, detail]) => ({
      framework: fw.framework,
      control: ctrl,
      ...detail,
    }))
  ).sort((a, b) => (a.status === 'FAIL' ? -1 : 1))

  return (
    <div className="overflow-auto">
      <table className="w-full border-collapse">
        <thead className="sticky top-0 bg-bg-secondary">
          <tr className="border-b border-bg-border">
            {['Framework', 'Control', 'Status', 'Rule', 'Finding'].map((h) => (
              <th key={h} className="label px-4 py-3 text-left">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {allControls.map((c, i) => (
            <tr key={`${c.framework}-${c.control}`} className="border-b border-bg-border hover:bg-bg-hover">
              <td className="px-4 py-2 font-mono text-xs text-accent-green">{c.framework}</td>
              <td className="px-4 py-2 font-mono text-xs text-text-secondary">{c.control}</td>
              <td className="px-4 py-2">
                <span className={`font-mono text-2xs uppercase tracking-widest px-2 py-0.5 ${
                  c.status === 'PASS'
                    ? 'text-accent-green border border-accent-muted'
                    : 'text-accent-red border border-red-900'
                }`}>
                  {c.status}
                </span>
              </td>
              <td className="px-4 py-2 font-mono text-xs text-text-muted">{(c as any).rule_id ?? '—'}</td>
              <td className="px-4 py-2 font-body text-xs text-text-secondary truncate max-w-[200px]">
                {(c as any).title ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
