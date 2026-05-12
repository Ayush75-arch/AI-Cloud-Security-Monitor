import { useEffect, useState } from 'react'
import { apiClient } from '../api/client'
import { SeverityBadge, Spinner, EmptyState } from '../components/ui'

interface AttackStep {
  finding_id: string
  rule_id: string
  title: string
  severity: string
  asset_name: string
  asset_type: string
  description: string
}

interface AttackPath {
  path_id: string
  title: string
  description: string
  overall_severity: string
  likelihood: string
  impact: string
  steps: AttackStep[]
}

const LIKELIHOOD_COLOR: Record<string, string> = {
  high:   '#ff3b5c',
  medium: '#ffcc00',
  low:    '#00aaff',
}

export default function AttackPathsPage() {
  const [paths, setPaths]       = useState<AttackPath[]>([])
  const [loading, setLoading]   = useState(true)
  const [selected, setSelected] = useState<AttackPath | null>(null)

  useEffect(() => {
    apiClient.get('/attack-paths')
      .then(r => {
        setPaths(r.data.data)
        if (r.data.data.length > 0) setSelected(r.data.data[0])
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full gap-3">
      <Spinner /><span className="font-mono text-xs text-text-secondary">Analyzing attack paths…</span>
    </div>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="px-6 py-4 border-b border-bg-border">
        <h1 className="font-display text-lg font-bold text-text-primary">Attack Path Analysis</h1>
        <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
          Chained misconfiguration exploits · {paths.length} paths identified
        </p>
      </div>

      {paths.length === 0 ? (
        <div className="flex items-center justify-center flex-1">
          <div className="text-center space-y-2">
            <div className="text-4xl opacity-10">◈</div>
            <div className="font-mono text-xs text-accent-green uppercase tracking-widest">No attack paths detected</div>
            <div className="font-mono text-2xs text-text-muted">Run a scan to analyze findings for attack chains</div>
          </div>
        </div>
      ) : (
        <div className="flex flex-1 overflow-hidden">
          {/* Path list */}
          <div className="w-80 flex-shrink-0 border-r border-bg-border overflow-auto">
            {paths.map((path) => (
              <button
                key={path.path_id}
                onClick={() => setSelected(path)}
                className={`w-full text-left px-4 py-3 border-b border-bg-border transition-colors ${
                  selected?.path_id === path.path_id
                    ? 'bg-bg-hover border-l-2 border-l-accent-red'
                    : 'hover:bg-bg-hover border-l-2 border-l-transparent'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={path.overall_severity as any} />
                  <span
                    className="font-mono text-2xs uppercase tracking-widest ml-auto"
                    style={{ color: LIKELIHOOD_COLOR[path.likelihood] }}
                  >
                    {path.likelihood} likelihood
                  </span>
                </div>
                <div className="font-body text-xs text-text-primary leading-snug">{path.title}</div>
                <div className="font-mono text-2xs text-text-muted mt-1">{path.steps.length} steps · {path.path_id}</div>
              </button>
            ))}
          </div>

          {/* Path detail */}
          {selected && (
            <div className="flex-1 overflow-auto p-6 space-y-6">
              {/* Header */}
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <SeverityBadge severity={selected.overall_severity as any} />
                  <span className="font-mono text-xs text-text-muted">{selected.path_id}</span>
                  <span
                    className="font-mono text-2xs uppercase tracking-widest ml-auto"
                    style={{ color: LIKELIHOOD_COLOR[selected.likelihood] }}
                  >
                    ● {selected.likelihood} likelihood
                  </span>
                </div>
                <h2 className="font-display text-base font-bold text-text-primary">{selected.title}</h2>
                <p className="font-body text-sm text-text-secondary mt-1 leading-relaxed">{selected.description}</p>
              </div>

              {/* Attack chain visualization */}
              <section>
                <div className="label mb-3">Attack Chain</div>
                <div className="space-y-0">
                  {selected.steps.map((step, i) => (
                    <div key={step.rule_id}>
                      <div className="flex gap-3">
                        {/* Step indicator */}
                        <div className="flex flex-col items-center">
                          <div className={`w-7 h-7 flex items-center justify-center font-mono text-xs font-bold border ${
                            step.severity === 'critical' ? 'border-accent-red text-accent-red bg-red-950' :
                            step.severity === 'high'     ? 'border-orange-500 text-orange-400 bg-orange-950' :
                            'border-accent-yellow text-accent-yellow bg-yellow-950'
                          }`}>
                            {i + 1}
                          </div>
                          {i < selected.steps.length - 1 && (
                            <div className="w-px flex-1 bg-bg-border my-1 min-h-[20px]" />
                          )}
                        </div>

                        {/* Step content */}
                        <div className="flex-1 pb-4">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-xs text-accent-green">{step.rule_id}</span>
                            <SeverityBadge severity={step.severity as any} />
                          </div>
                          <div className="font-body text-sm text-text-primary font-medium">{step.title}</div>
                          <div className="font-mono text-2xs text-text-muted mt-0.5">
                            {step.asset_type.replace(/_/g, ' ')} · <span className="text-accent-green">{step.asset_name}</span>
                          </div>
                          <p className="font-body text-xs text-text-secondary mt-1 leading-relaxed">{step.description}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Impact */}
              <section className="border border-red-900 bg-red-950/30 px-4 py-3">
                <div className="label text-accent-red mb-2">Business Impact</div>
                <p className="font-body text-sm text-text-secondary leading-relaxed">{selected.impact}</p>
              </section>

              {/* Remediation priority */}
              <section className="border border-accent-muted px-4 py-3">
                <div className="label text-accent-green mb-2">Remediation Priority</div>
                <p className="font-body text-sm text-text-secondary leading-relaxed">
                  Fix <span className="text-accent-green font-medium">{selected.steps[0]?.rule_id}</span> first —
                  it is the entry point of this attack chain. Resolving it breaks the entire path
                  even if subsequent findings remain open.
                </p>
              </section>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
