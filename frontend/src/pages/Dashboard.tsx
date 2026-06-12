import { useEffect, useState } from 'react'
import { getDashboardStats, getCompliance } from '../api'
import { useDashboardStore } from '../store'
import { StatCards, RiskPanel } from '../components/dashboard/StatCards'
import { SeverityBarChart, SeverityPieChart } from '../components/dashboard/SeverityChart'
import { CompliancePanel } from '../components/dashboard/CompliancePanel'
import { ScanTrigger } from '../components/scans/ScanTrigger'
import { Spinner } from '../components/ui'
import type { ComplianceSummary } from '../types'

export default function DashboardPage() {
  const { stats, setStats } = useDashboardStore()
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null)
  const [loading, setLoading] = useState(!stats)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const [s, c] = await Promise.all([getDashboardStats(), getCompliance()])
        setStats(s)
        setCompliance(c)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full gap-3">
        <Spinner size={20} />
        <span className="font-mono text-xs text-text-secondary">Loading dashboard…</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full font-mono text-xs text-accent-red">
        ✕ {error}
      </div>
    )
  }

  return (
    /* Full-height scrollable container */
    <div className="h-full overflow-y-auto">
      {/* Page header */}
      <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between sticky top-0 bg-bg-primary z-10">
        <div>
          <h1 className="font-display text-lg font-bold text-text-primary">Security Overview</h1>
          <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
            Cloud Security Posture Management
          </p>
        </div>
        <div className="font-mono text-2xs text-accent-green flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse-green inline-block" />
          Live
        </div>
      </div>

      {/* Stat bar */}
      {stats && <StatCards stats={stats} />}

      {/* Risk + compliance inline */}
      {stats && <RiskPanel stats={stats} />}

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-0 border-t border-bg-border">
        <div className="border-r border-bg-border">
          {stats && <SeverityBarChart stats={stats} />}
        </div>
        <div>
          {stats && <SeverityPieChart stats={stats} />}
        </div>
      </div>

      {/* Compliance + Scan row */}
      <div className="grid grid-cols-2 gap-0 border-t border-bg-border">
        <div className="border-r border-bg-border">
          {compliance
            ? <CompliancePanel data={compliance} />
            : <div className="p-6 font-mono text-xs text-text-muted">No compliance data yet.</div>
          }
        </div>
        <div>
          <ScanTrigger />
        </div>
      </div>
    </div>
  )
}
