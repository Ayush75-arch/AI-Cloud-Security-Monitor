import { useEffect, useState } from 'react'
import { getCompliance } from '../api'
import { CompliancePanel, ComplianceControlTable } from '../components/dashboard/CompliancePanel'
import { Spinner } from '../components/ui'
import type { ComplianceSummary } from '../types'

export default function CompliancePage() {
  const [data, setData]     = useState<ComplianceSummary | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getCompliance().then(setData).finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full gap-3">
      <Spinner /><span className="font-mono text-xs text-text-secondary">Loading compliance…</span>
    </div>
  )

  if (!data) return (
    <div className="flex items-center justify-center h-full font-mono text-xs text-text-muted">
      No compliance data. Run a scan first.
    </div>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="px-6 py-4 border-b border-bg-border">
        <h1 className="font-display text-lg font-bold text-text-primary">Compliance</h1>
        <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
          CIS · NIST · PCI-DSS
        </p>
      </div>

      <div className="flex-1 grid grid-cols-3 overflow-hidden">
        <div className="border-r border-bg-border overflow-auto">
          <CompliancePanel data={data} />
        </div>
        <div className="col-span-2 overflow-auto">
          <div className="px-4 py-3 border-b border-bg-border">
            <span className="label">Control Details</span>
          </div>
          <ComplianceControlTable data={data} />
        </div>
      </div>
    </div>
  )
}
