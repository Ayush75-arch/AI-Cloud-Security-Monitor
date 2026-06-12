import { useState } from 'react'
import { createScan, listScans } from '../../api'
import { useScanStore } from '../../store'
import { Spinner, StatusBadge } from '../ui'

const SERVICES = ['s3', 'iam', 'ec2', 'vpc']
const REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-south-1']
const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

export function ScanTrigger() {
  const { activeScan, isScanning, setActiveScan, setIsScanning, setScans, updateScan } = useScanStore()
  const [accountId, setAccountId] = useState('123456789012')
  const [region, setRegion] = useState('us-east-1')
  const [services, setServices] = useState<string[]>(SERVICES)
  const [error, setError] = useState<string | null>(null)

  const toggleService = (svc: string) =>
    setServices((prev) => prev.includes(svc) ? prev.filter((s) => s !== svc) : [...prev, svc])

  const handleScan = async () => {
    if (isScanning) return
    setError(null)
    setIsScanning(true)

    try {
      const { scans: existing } = await listScans(1, 50)
      const alreadyRunning = existing.find(
        (s) => (s.status === 'running' || s.status === 'pending') &&
                s.account_id === accountId &&
                s.region === region
      )
      if (alreadyRunning) {
        setError('A scan is already running for this account/region.')
        setIsScanning(false)
        return
      }

      const scan = await createScan({ account_id: accountId, region, services })
      setActiveScan(scan)

      // Fix 5: use SSE stream instead of polling interval
      const token = localStorage.getItem('cg_token')
      const url = `${BASE_URL}/api/v1/scans/${scan.id}/stream`
      const headers: Record<string, string> = token
        ? { Authorization: `Bearer ${token}` }
        : {}

      // EventSource doesn't support custom headers — use fetch with ReadableStream
      const response = await fetch(url, { headers })
      if (!response.body) throw new Error('No SSE stream body')

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      const pump = async () => {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const payload = JSON.parse(line.slice(6))
                updateScan({ ...scan, ...payload })
                if (payload.status === 'completed' || payload.status === 'failed') {
                  setActiveScan({ ...scan, ...payload })
                  setIsScanning(false)
                  const { scans: refreshed } = await listScans(1, 50)
                  setScans(refreshed)
                  return
                }
              } catch { /* ignore parse errors */ }
            }
          }
        }
        setIsScanning(false)
      }

      pump().catch(() => setIsScanning(false))

    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed')
      setIsScanning(false)
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="label">New Scan</span>
        {activeScan && <StatusBadge status={activeScan.status} />}
      </div>
      <div className="p-4 space-y-4">
        <div>
          <label className="label block mb-1">AWS Account ID</label>
          <input
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            className="w-full bg-bg-secondary border border-bg-border px-3 py-2 font-mono text-xs text-text-primary focus:outline-none focus:border-accent-green"
            placeholder="123456789012"
            disabled={isScanning}
          />
        </div>

        <div>
          <label className="label block mb-1">Region</label>
          <select
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            className="w-full bg-bg-secondary border border-bg-border px-3 py-2 font-mono text-xs text-text-primary focus:outline-none focus:border-accent-green"
            disabled={isScanning}
          >
            {REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        <div>
          <label className="label block mb-2">Services</label>
          <div className="flex gap-2 flex-wrap">
            {SERVICES.map((svc) => (
              <button
                key={svc}
                onClick={() => toggleService(svc)}
                disabled={isScanning}
                className={`font-mono text-xs uppercase tracking-widest px-3 py-1 border transition-colors ${
                  services.includes(svc)
                    ? 'bg-accent-muted border-accent-green text-accent-green'
                    : 'border-bg-border text-text-muted hover:border-text-muted'
                }`}
              >
                {svc}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="font-mono text-xs text-accent-red border border-red-900 px-3 py-2">
            ✕ {error}
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={isScanning || services.length === 0}
          className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-40"
        >
          {isScanning ? (
            <>
              <Spinner size={12} />
              Scanning…
            </>
          ) : (
            '▷  Run Scan'
          )}
        </button>

        {activeScan && isScanning && (
          <div className="border border-bg-border px-3 py-2 space-y-1">
            <div className="label">Live Status</div>
            <div className="font-mono text-xs text-accent-green animate-pulse">
              ● Scanning {activeScan.account_id} / {activeScan.region}
            </div>
            <div className="font-mono text-2xs text-text-muted">
              Services: {activeScan.services.join(', ')}
            </div>
          </div>
        )}

        {activeScan && !isScanning && activeScan.status === 'completed' && (
          <div className="border border-accent-muted px-3 py-2 space-y-1">
            <div className="label text-accent-green">Scan Complete</div>
            <div className="font-mono text-xs text-text-secondary">
              {activeScan.total_findings} findings —{' '}
              <span className="text-accent-red">{activeScan.critical_count}C</span>{' '}
              <span className="text-orange-400">{activeScan.high_count}H</span>{' '}
              <span className="text-accent-yellow">{activeScan.medium_count}M</span>{' '}
              <span className="text-accent-blue">{activeScan.low_count}L</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
