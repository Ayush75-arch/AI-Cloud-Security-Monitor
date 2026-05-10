import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie,
} from 'recharts'
import type { DashboardStats } from '../../types'

const COLORS = {
  critical: '#ff3b5c',
  high:     '#ff8c00',
  medium:   '#ffcc00',
  low:      '#00aaff',
}

interface Props { stats: DashboardStats }

export function SeverityBarChart({ stats }: Props) {
  const { severity_breakdown: s } = stats
  const data = [
    { name: 'Critical', value: s.critical, color: COLORS.critical },
    { name: 'High',     value: s.high,     color: COLORS.high },
    { name: 'Medium',   value: s.medium,   color: COLORS.medium },
    { name: 'Low',      value: s.low,      color: COLORS.low },
  ]

  return (
    <div className="panel h-full">
      <div className="panel-header">
        <span className="label">Severity Distribution</span>
      </div>
      <div className="p-4" style={{ height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} barCategoryGap="30%">
            <XAxis
              dataKey="name"
              tick={{ fill: '#7a8999', fontSize: 10, fontFamily: 'IBM Plex Mono' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#7a8999', fontSize: 10, fontFamily: 'IBM Plex Mono' }}
              axisLine={false}
              tickLine={false}
              width={28}
            />
            <Tooltip
              contentStyle={{
                background: '#131619',
                border: '1px solid #1e2328',
                borderRadius: 0,
                fontFamily: 'IBM Plex Mono',
                fontSize: 11,
                color: '#e8edf2',
              }}
              cursor={{ fill: 'rgba(255,255,255,0.03)' }}
            />
            <Bar dataKey="value" radius={0}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} fillOpacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export function SeverityPieChart({ stats }: Props) {
  const { severity_breakdown: s } = stats
  const total = s.critical + s.high + s.medium + s.low
  const data = [
    { name: 'Critical', value: s.critical, color: COLORS.critical },
    { name: 'High',     value: s.high,     color: COLORS.high },
    { name: 'Medium',   value: s.medium,   color: COLORS.medium },
    { name: 'Low',      value: s.low,      color: COLORS.low },
  ].filter(d => d.value > 0)

  return (
    <div className="panel h-full">
      <div className="panel-header">
        <span className="label">Risk Breakdown</span>
        <span className="font-mono text-xs text-text-secondary">{total} total</span>
      </div>
      <div className="p-4 flex items-center gap-4" style={{ height: 200 }}>
        <ResponsiveContainer width="60%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%" cy="50%"
              innerRadius={50} outerRadius={70}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} fillOpacity={0.9} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#131619',
                border: '1px solid #1e2328',
                borderRadius: 0,
                fontFamily: 'IBM Plex Mono',
                fontSize: 11,
                color: '#e8edf2',
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        <div className="flex flex-col gap-2">
          {data.map((d) => (
            <div key={d.name} className="flex items-center gap-2">
              <span className="w-2 h-2 inline-block" style={{ background: d.color }} />
              <span className="font-mono text-xs text-text-secondary">{d.name}</span>
              <span className="font-mono text-xs text-text-primary ml-auto pl-4 tabular-nums">{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
