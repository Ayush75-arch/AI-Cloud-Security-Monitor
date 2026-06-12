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

const TOOLTIP_STYLE = {
  background: '#131619',
  border: '1px solid #1e2328',
  borderRadius: 0,
  fontFamily: 'IBM Plex Mono',
  fontSize: 11,
  color: '#e8edf2',
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
              contentStyle={TOOLTIP_STYLE}
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
            />
            {/* activeBar={false} prevents recharts from overriding fill with black on click */}
            <Bar dataKey="value" radius={0} activeBar={false}>
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={entry.color}
                  fillOpacity={0.85}
                  style={{ outline: 'none' }}
                />
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

  // Custom active shape that preserves the slice color instead of going black
  const renderActiveShape = (props: any) => {
    const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props
    return (
      <g>
        <path
          d={`M ${cx} ${cy}`}
          fill="none"
        />
        <path
          stroke="none"
          fill={fill}
          fillOpacity={1}
          d={describeArc(cx, cy, innerRadius, outerRadius + 6, startAngle, endAngle)}
        />
      </g>
    )
  }

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
              activeShape={renderActiveShape}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={entry.color}
                  fillOpacity={0.9}
                  style={{ outline: 'none' }}
                />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>

        <div className="flex flex-col gap-2">
          {data.map((d) => (
            <div key={d.name} className="flex items-center gap-2">
              <span className="w-2 h-2 inline-block flex-shrink-0" style={{ background: d.color }} />
              <span className="font-mono text-xs text-text-secondary">{d.name}</span>
              <span className="font-mono text-xs text-text-primary ml-auto pl-4 tabular-nums">{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Helper: SVG arc path for active pie slice ─────────────────────────────────

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = (angleDeg - 90) * (Math.PI / 180)
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) }
}

function describeArc(
  cx: number, cy: number,
  innerR: number, outerR: number,
  startAngle: number, endAngle: number,
): string {
  const s1 = polarToCartesian(cx, cy, outerR, endAngle)
  const e1 = polarToCartesian(cx, cy, outerR, startAngle)
  const s2 = polarToCartesian(cx, cy, innerR, endAngle)
  const e2 = polarToCartesian(cx, cy, innerR, startAngle)
  const large = endAngle - startAngle > 180 ? 1 : 0
  return [
    `M ${s1.x} ${s1.y}`,
    `A ${outerR} ${outerR} 0 ${large} 0 ${e1.x} ${e1.y}`,
    `L ${e2.x} ${e2.y}`,
    `A ${innerR} ${innerR} 0 ${large} 1 ${s2.x} ${s2.y}`,
    'Z',
  ].join(' ')
}
