import { useState, useEffect } from 'react'
import { listFindings } from '../api'
import { FindingsTable } from '../components/findings/FindingsTable'
import type { Finding, Severity } from '../types'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const STATUSES   = ['open', 'suppressed', 'resolved']

export default function FindingsPage() {
  const [findings, setFindings]           = useState<Finding[]>([])
  const [loading, setLoading]             = useState(true)
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)
  const [statusFilter, setStatusFilter]   = useState<string>('open')
  const [page, setPage]                   = useState(1)
  const [total, setTotal]                 = useState(0)
  const LIMIT = 100

  const load = async () => {
    setLoading(true)
    try {
      const { findings: f, meta } = await listFindings({
        severity: severityFilter ?? undefined,
        status: statusFilter || undefined,
        page,
        limit: LIMIT,
      })
      setFindings(f)
      setTotal(meta.total)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [severityFilter, statusFilter, page])

  const handleSuppressed = (id: string) => {
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status: 'suppressed' } : f))
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
        <div>
          <h1 className="font-display text-lg font-bold text-text-primary">Findings</h1>
          <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
            {total} total · {findings.filter(f => f.status === 'open').length} shown open
          </p>
        </div>
        <button onClick={load} className="btn-ghost text-xs">↺ Refresh</button>
      </div>

      {/* Filters */}
      <div className="px-6 py-3 border-b border-bg-border flex items-center gap-4 flex-wrap">
        <span className="label">Severity</span>
        <div className="flex gap-1">
          <button
            onClick={() => setSeverityFilter(null)}
            className={`font-mono text-2xs uppercase tracking-widest px-3 py-1 border transition-colors ${
              !severityFilter ? 'border-accent-green text-accent-green bg-accent-muted' : 'border-bg-border text-text-muted hover:border-text-muted'
            }`}
          >
            All
          </button>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
              className={`font-mono text-2xs uppercase tracking-widest px-3 py-1 border transition-colors ${
                severityFilter === s ? 'border-accent-green text-accent-green bg-accent-muted' : 'border-bg-border text-text-muted hover:border-text-muted'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="w-px h-4 bg-bg-border" />

        <span className="label">Status</span>
        <div className="flex gap-1">
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(statusFilter === s ? '' : s)}
              className={`font-mono text-2xs uppercase tracking-widest px-3 py-1 border transition-colors ${
                statusFilter === s ? 'border-accent-green text-accent-green bg-accent-muted' : 'border-bg-border text-text-muted hover:border-text-muted'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-hidden">
        <FindingsTable
          findings={findings}
          loading={loading}
          onSuppressed={handleSuppressed}
        />
      </div>

      {/* Pagination */}
      {total > LIMIT && (
        <div className="px-6 py-3 border-t border-bg-border flex items-center gap-3">
          <span className="font-mono text-xs text-text-muted">
            Page {page} of {Math.ceil(total / LIMIT)}
          </span>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="btn-ghost disabled:opacity-30">←</button>
          <button onClick={() => setPage(p => p + 1)} disabled={page * LIMIT >= total} className="btn-ghost disabled:opacity-30">→</button>
        </div>
      )}
    </div>
  )
}
