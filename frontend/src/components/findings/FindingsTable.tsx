import { useState } from 'react'
import { SeverityBadge, FindingStatusBadge, EmptyState, Spinner } from '../ui'
import { suppressFinding } from '../../api'
import type { Finding, Severity } from '../../types'
import { formatDistanceToNow } from 'date-fns'

interface Props {
  findings: Finding[]
  loading?: boolean
  onSuppressed?: (id: string) => void
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }

export function FindingsTable({ findings, loading, onSuppressed }: Props) {
  const [selected, setSelected] = useState<Finding | null>(null)
  const [suppressing, setSuppressing] = useState<string | null>(null)

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  )

  const handleSuppress = async (finding: Finding) => {
    const reason = window.prompt('Suppression reason:')
    if (!reason) return
    setSuppressing(finding.id)
    try {
      await suppressFinding(finding.id, reason)
      onSuppressed?.(finding.id)
    } finally {
      setSuppressing(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16 gap-3">
        <Spinner />
        <span className="font-mono text-xs text-text-secondary">Loading findings…</span>
      </div>
    )
  }

  if (!sorted.length) return <EmptyState message="No findings" />

  return (
    <div className="flex h-full">
      {/* Table */}
      <div className={`overflow-auto ${selected ? 'w-1/2 border-r border-bg-border' : 'w-full'}`}>
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-bg-secondary z-10">
            <tr className="border-b border-bg-border">
              {['Severity', 'Rule', 'Title', 'Asset', 'Status', 'Age', ''].map((h) => (
                <th key={h} className="label px-4 py-3 font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((f, i) => (
              <tr
                key={f.id}
                onClick={() => setSelected(selected?.id === f.id ? null : f)}
                className={`border-b border-bg-border cursor-pointer transition-colors animate-fade-in
                  ${selected?.id === f.id ? 'bg-bg-hover border-l-2 border-l-accent-green' : 'hover:bg-bg-hover'}
                `}
                style={{ animationDelay: `${i * 20}ms`, animationFillMode: 'both' }}
              >
                <td className="px-4 py-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-accent-green">{f.rule_id}</td>
                <td className="px-4 py-3 font-body text-sm text-text-primary max-w-xs truncate">{f.title}</td>
                <td className="px-4 py-3 font-mono text-xs text-text-secondary truncate max-w-[120px]">
                  {f.asset?.asset_name ?? '—'}
                </td>
                <td className="px-4 py-3">
                  <FindingStatusBadge status={f.status} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-text-muted whitespace-nowrap">
                  {formatDistanceToNow(new Date(f.created_at), { addSuffix: true })}
                </td>
                <td className="px-4 py-3">
                  {f.status === 'open' && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleSuppress(f) }}
                      disabled={suppressing === f.id}
                      className="font-mono text-2xs uppercase tracking-widest text-text-muted hover:text-accent-yellow px-2 py-1 border border-transparent hover:border-bg-border transition-colors"
                    >
                      {suppressing === f.id ? '…' : 'Suppress'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail panel */}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function FindingDetail({ finding: f, onClose }: { finding: Finding; onClose: () => void }) {
  const compliance = Object.entries(f.compliance_mappings)

  return (
    <div className="w-1/2 overflow-auto p-5 space-y-5 animate-slide-up">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={f.severity} />
            <span className="font-mono text-xs text-accent-green">{f.rule_id}</span>
          </div>
          <h2 className="font-display text-base font-semibold text-text-primary">{f.title}</h2>
        </div>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary font-mono text-xs px-2">✕</button>
      </div>

      {/* Description */}
      <section>
        <div className="label mb-2">Description</div>
        <p className="font-body text-sm text-text-secondary leading-relaxed">{f.description}</p>
      </section>

      {/* Asset */}
      {f.asset && (
        <section className="border border-bg-border px-4 py-3 space-y-1">
          <div className="label">Affected Asset</div>
          <div className="font-mono text-xs text-accent-green">{f.asset.asset_name}</div>
          <div className="font-mono text-2xs text-text-muted">{f.asset.asset_type} · {f.asset.region}</div>
        </section>
      )}

      {/* Compliance */}
      {compliance.length > 0 && (
        <section>
          <div className="label mb-2">Compliance Mappings</div>
          <div className="flex flex-wrap gap-2">
            {compliance.map(([fw, ctrl]) => (
              <span key={fw} className="font-mono text-2xs px-2 py-1 border border-bg-border text-text-secondary">
                {fw}: <span className="text-accent-green">{ctrl}</span>
              </span>
            ))}
          </div>
        </section>
      )}

      {/* AI Analysis */}
      {f.ai_explanation && (
        <section>
          <div className="label mb-2 text-accent-green">AI Analysis</div>
          <div className="border-l-2 border-accent-muted pl-4 space-y-3">
            <div>
              <div className="label mb-1">Why It's Dangerous</div>
              <p className="font-body text-sm text-text-secondary leading-relaxed">{f.ai_explanation}</p>
            </div>
            {f.ai_attack_scenario && (
              <div>
                <div className="label mb-1">Attack Scenario</div>
                <p className="font-body text-sm text-accent-red/80 leading-relaxed">{f.ai_attack_scenario}</p>
              </div>
            )}
            {f.ai_remediation && (
              <div>
                <div className="label mb-1">Remediation</div>
                <p className="font-body text-sm text-text-secondary leading-relaxed whitespace-pre-line">{f.ai_remediation}</p>
              </div>
            )}
          </div>
        </section>
      )}

      {!f.ai_explanation && (
        <div className="border border-bg-border px-4 py-3 font-mono text-xs text-text-muted">
          ● AI analysis pending — running post-scan…
        </div>
      )}
    </div>
  )
}
