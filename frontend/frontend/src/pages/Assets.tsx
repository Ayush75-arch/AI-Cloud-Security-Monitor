import { useEffect, useState } from 'react'
import { listAssets } from '../api'
import { EmptyState, Spinner } from '../components/ui'
import { formatDistanceToNow } from 'date-fns'
import type { Asset, AssetType } from '../types'

const ASSET_ICONS: Record<string, string> = {
  s3_bucket:      '◈',
  iam_role:       '◻',
  iam_policy:     '◼',
  iam_user:       '◷',
  ec2_instance:   '◇',
  security_group: '◈',
  vpc:            '⬡',
  subnet:         '◦',
}

const ASSET_TYPES: AssetType[] = [
  's3_bucket', 'iam_role', 'iam_policy', 'iam_user',
  'ec2_instance', 'security_group', 'vpc', 'subnet',
]

export default function AssetsPage() {
  const [assets, setAssets]         = useState<Asset[]>([])
  const [loading, setLoading]       = useState(true)
  const [typeFilter, setTypeFilter] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    listAssets({ asset_type: typeFilter ?? undefined, limit: 200 })
      .then(({ assets: a }) => setAssets(a))
      .finally(() => setLoading(false))
  }, [typeFilter])

  const counts = ASSET_TYPES.reduce<Record<string, number>>((acc, t) => {
    acc[t] = assets.filter(a => a.asset_type === t).length
    return acc
  }, {})

  return (
    <div className="flex flex-col h-full">
      <div className="px-6 py-4 border-b border-bg-border">
        <h1 className="font-display text-lg font-bold text-text-primary">Cloud Assets</h1>
        <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
          {assets.length} resources scanned
        </p>
      </div>

      {/* Asset type summary bar */}
      <div className="flex border-b border-bg-border overflow-x-auto">
        <button
          onClick={() => setTypeFilter(null)}
          className={`px-5 py-3 font-mono text-xs uppercase tracking-widest whitespace-nowrap border-r border-bg-border transition-colors ${
            !typeFilter ? 'text-accent-green bg-accent-muted' : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          All ({assets.length})
        </button>
        {ASSET_TYPES.filter(t => counts[t] > 0).map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(typeFilter === t ? null : t)}
            className={`px-5 py-3 font-mono text-xs uppercase tracking-widest whitespace-nowrap border-r border-bg-border transition-colors ${
              typeFilter === t ? 'text-accent-green bg-accent-muted' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {ASSET_ICONS[t]} {t.replace('_', ' ')} ({counts[t]})
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center py-16 gap-3">
            <Spinner /><span className="font-mono text-xs text-text-secondary">Loading assets…</span>
          </div>
        ) : assets.length === 0 ? (
          <EmptyState message="No assets found. Run a scan first." />
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-bg-secondary">
              <tr className="border-b border-bg-border">
                {['Type', 'Name', 'Resource ID', 'Region', 'Discovered'].map(h => (
                  <th key={h} className="label px-4 py-3 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assets.map((asset, i) => (
                <tr
                  key={asset.id}
                  className="border-b border-bg-border hover:bg-bg-hover animate-fade-in"
                  style={{ animationDelay: `${i * 10}ms`, animationFillMode: 'both' }}
                >
                  <td className="px-4 py-2">
                    <span className="font-mono text-xs px-2 py-0.5 border border-bg-border text-text-secondary uppercase">
                      {ASSET_ICONS[asset.asset_type]} {asset.asset_type.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-accent-green">{asset.asset_name}</td>
                  <td className="px-4 py-2 font-mono text-2xs text-text-muted max-w-[200px] truncate">{asset.asset_id}</td>
                  <td className="px-4 py-2 font-mono text-xs text-text-secondary">{asset.region}</td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {formatDistanceToNow(new Date(asset.created_at), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
