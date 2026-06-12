import { useEffect, useState } from 'react'
import { listScans } from '../api'
import { StatusBadge, EmptyState, Spinner } from '../components/ui'
import { ScanTrigger } from '../components/scans/ScanTrigger'
import { formatDistanceToNow } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import type { Scan } from '../types'

export default function ScansPage() {
  const [scans, setScans]     = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const navigate              = useNavigate()

  useEffect(() => {
    listScans(1, 50).then(({ scans: s }) => setScans(s)).finally(() => setLoading(false))
  }, [])

  return (
    <div className="flex flex-col h-full">
      <div className="px-6 py-4 border-b border-bg-border">
        <h1 className="font-display text-lg font-bold text-text-primary">Scans</h1>
        <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
          Scan history &amp; management
        </p>
      </div>

      <div className="flex-1 grid grid-cols-3 overflow-hidden">
        {/* Scan list */}
        <div className="col-span-2 border-r border-bg-border overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-3">
              <Spinner /><span className="font-mono text-xs text-text-secondary">Loading scans…</span>
            </div>
          ) : scans.length === 0 ? (
            <EmptyState message="No scans yet" />
          ) : (
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-bg-secondary">
                <tr className="border-b border-bg-border">
                  {['Status', 'Account', 'Region', 'Findings', 'Services', 'Started', ''].map(h => (
                    <th key={h} className="label px-4 py-3 text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-bg-border hover:bg-bg-hover cursor-pointer"
                    onClick={() => navigate(`/findings?scan_id=${scan.id}`)}
                  >
                    <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-text-primary">{scan.account_id}</td>
                    <td className="px-4 py-3 font-mono text-xs text-text-secondary">{scan.region}</td>
                    <td className="px-4 py-3">
                      {scan.status === 'completed' ? (
                        <span className="font-mono text-xs">
                          <span className="text-accent-red">{scan.critical_count}C</span>{' '}
                          <span className="text-orange-400">{scan.high_count}H</span>{' '}
                          <span className="text-accent-yellow">{scan.medium_count}M</span>{' '}
                          <span className="text-accent-blue">{scan.low_count}L</span>
                        </span>
                      ) : (
                        <span className="font-mono text-xs text-text-muted">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-text-muted">
                      {scan.services.join(', ')}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-text-muted">
                      {scan.started_at
                        ? formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })
                        : '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-accent-green">→</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Trigger */}
        <div className="overflow-auto p-4">
          <ScanTrigger />
        </div>
      </div>
    </div>
  )
}
