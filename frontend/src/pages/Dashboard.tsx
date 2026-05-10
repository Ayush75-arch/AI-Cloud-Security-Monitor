import { useEffect } from 'react'
import { getDashboardStats, getCompliance } from '../api'
import { useDashboardStore } from '../store'
import { StatCards, RiskPanel } from '../components/dashboard/StatCards'
import { SeverityBarChart, SeverityPieChart } from '../components/dashboard/SeverityChart'
import { CompliancePanel } from '../components/dashboard/CompliancePanel'
import { ScanTrigger } from '../components/scans/ScanTrigger'
import { Spinner } from '../components/ui'
import { useState } from 'react'
import type { ComplianceSummary } from '../types'

export default function DashboardPage() {
  const { stats, setStats } = useDashboardStore()
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null)
  const [loading, setLoading] = useState(!stats)

  useEffect(() => {
    const load = async () => {
      try {
        const [s, c] = await Promise.all([getDashboardStats(), getCompliance()])
        setStats(s)
        setCompliance(c)
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
        <span className="font-mono text-xs text-text-secondary">Initializing CloudGuard…</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full animate-fade-in">
      {/* Page header */}
      <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
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

      {/* Main grid */}
      <div className="flex-1 grid grid-cols-3 gap-0 overflow-hidden border-t border-bg-border">
        {/* Charts col */}
        <div className="col-span-2 grid grid-rows-2 border-r border-bg-border overflow-hidden">
          <div className="border-b border-bg-border">
            {stats && <SeverityBarChart stats={stats} />}
          </div>
          <div>
            {stats && <SeverityPieChart stats={stats} />}
          </div>
        </div>

        {/* Right col */}
        <div className="grid grid-rows-2 overflow-hidden">
          <div className="border-b border-bg-border overflow-auto">
            {compliance && <CompliancePanel data={compliance} />}
          </div>
          <div className="overflow-auto">
            <ScanTrigger />
          </div>
        </div>
      </div>
    </div>
  )
}
