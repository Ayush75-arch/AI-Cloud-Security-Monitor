import { useState } from 'react'
import { apiClient } from '../api/client'
import { SeverityBadge, Spinner, EmptyState } from '../components/ui'

interface IaCFinding {
  rule_id: string
  title: string
  description: string
  severity: string
  file_path: string
  line_number: number
  resource_type: string
  resource_name: string
  compliance_mappings: Record<string, string>
  remediation: string
}

const DEMO_TF = `# Intentionally misconfigured Terraform — for demo
resource "aws_s3_bucket" "customer_data" {
  bucket = "prod-customer-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-tier"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "dev_access" {
  name = "DevFullAccess"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "main" {
  password = "SuperSecret123"
}
`

export default function IaCPage() {
  const [content, setContent]     = useState(DEMO_TF)
  const [filename, setFilename]   = useState('main.tf')
  const [findings, setFindings]   = useState<IaCFinding[]>([])
  const [loading, setLoading]     = useState(false)
  const [scanned, setScanned]     = useState(false)
  const [selected, setSelected]   = useState<IaCFinding | null>(null)

  const handleScan = async () => {
    setLoading(true)
    setScanned(false)
    setSelected(null)
    try {
      const res = await apiClient.post('/iac/scan', { content, filename })
      setFindings(res.data.data)
      setScanned(true)
    } finally {
      setLoading(false)
    }
  }

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await file.text()
    setContent(text)
    setFilename(file.name)
    setScanned(false)
    setFindings([])
  }

  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-bg-border">
        <h1 className="font-display text-lg font-bold text-text-primary">IaC Scanner</h1>
        <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
          Terraform static analysis — detect misconfigs before deployment
        </p>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: editor */}
        <div className="flex flex-col w-1/2 border-r border-bg-border">
          {/* Toolbar */}
          <div className="px-4 py-2 border-b border-bg-border flex items-center gap-3">
            <span className="font-mono text-xs text-accent-green">{filename}</span>
            <label className="btn-ghost cursor-pointer text-xs ml-auto">
              ↑ Upload .tf
              <input type="file" accept=".tf" className="hidden" onChange={handleUpload} />
            </label>
            <button
              onClick={handleScan}
              disabled={loading || !content.trim()}
              className="btn-primary flex items-center gap-2 disabled:opacity-40"
            >
              {loading ? <><Spinner size={11} /> Scanning…</> : '▷ Scan'}
            </button>
          </div>

          {/* Editor */}
          <textarea
            value={content}
            onChange={(e) => { setContent(e.target.value); setScanned(false) }}
            className="flex-1 bg-bg-primary font-mono text-xs text-text-secondary p-4 resize-none focus:outline-none leading-relaxed"
            spellCheck={false}
            placeholder="Paste Terraform HCL here or upload a .tf file…"
          />
        </div>

        {/* Right: results */}
        <div className="flex flex-col w-1/2 overflow-hidden">
          {/* Summary bar */}
          {scanned && (
            <div className="px-4 py-2 border-b border-bg-border flex items-center gap-4">
              <span className="font-mono text-xs text-text-secondary">
                {findings.length} {findings.length === 1 ? 'finding' : 'findings'}
              </span>
              {['critical', 'high', 'medium', 'low'].map((s) =>
                severityCounts[s] ? (
                  <span key={s} className="font-mono text-2xs uppercase tracking-widest">
                    <span className={
                      s === 'critical' ? 'text-accent-red' :
                      s === 'high'     ? 'text-orange-400' :
                      s === 'medium'   ? 'text-accent-yellow' :
                                         'text-accent-blue'
                    }>{severityCounts[s]}{s[0].toUpperCase()}</span>
                  </span>
                ) : null
              )}
            </div>
          )}

          {/* Findings list / detail */}
          <div className="flex flex-1 overflow-hidden">
            <div className={`overflow-auto ${selected ? 'w-1/2 border-r border-bg-border' : 'w-full'}`}>
              {!scanned ? (
                <div className="flex flex-col items-center justify-center h-full text-text-muted font-mono text-xs gap-3">
                  <span className="text-4xl opacity-10">◈</span>
                  Paste Terraform and click Scan
                </div>
              ) : findings.length === 0 ? (
                <EmptyState message="No misconfigurations found ✓" />
              ) : (
                <table className="w-full border-collapse">
                  <thead className="sticky top-0 bg-bg-secondary">
                    <tr className="border-b border-bg-border">
                      {['Sev', 'Rule', 'Resource', 'Line'].map(h => (
                        <th key={h} className="label px-3 py-2 text-left">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => (
                      <tr
                        key={i}
                        onClick={() => setSelected(selected?.rule_id === f.rule_id && selected?.line_number === f.line_number ? null : f)}
                        className={`border-b border-bg-border cursor-pointer transition-colors hover:bg-bg-hover ${
                          selected === f ? 'bg-bg-hover border-l-2 border-l-accent-green' : ''
                        }`}
                      >
                        <td className="px-3 py-2"><SeverityBadge severity={f.severity as any} /></td>
                        <td className="px-3 py-2 font-mono text-xs text-accent-green">{f.rule_id}</td>
                        <td className="px-3 py-2 font-mono text-xs text-text-secondary truncate max-w-[100px]">{f.resource_name}</td>
                        <td className="px-3 py-2 font-mono text-xs text-text-muted">:{f.line_number}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Detail panel */}
            {selected && (
              <div className="w-1/2 overflow-auto p-4 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={selected.severity as any} />
                      <span className="font-mono text-xs text-accent-green">{selected.rule_id}</span>
                    </div>
                    <h3 className="font-display text-sm font-semibold text-text-primary">{selected.title}</h3>
                  </div>
                  <button onClick={() => setSelected(null)} className="font-mono text-xs text-text-muted hover:text-text-primary">✕</button>
                </div>

                <div className="border border-bg-border px-3 py-2 space-y-1">
                  <div className="label">Location</div>
                  <div className="font-mono text-xs text-accent-green">
                    {selected.resource_type} · {selected.resource_name}
                  </div>
                  <div className="font-mono text-2xs text-text-muted">line {selected.line_number}</div>
                </div>

                <section>
                  <div className="label mb-1">Issue</div>
                  <p className="font-body text-sm text-text-secondary leading-relaxed">{selected.description}</p>
                </section>

                {Object.keys(selected.compliance_mappings).length > 0 && (
                  <section>
                    <div className="label mb-2">Compliance</div>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(selected.compliance_mappings).map(([fw, ctrl]) => (
                        <span key={fw} className="font-mono text-2xs px-2 py-1 border border-bg-border text-text-secondary">
                          {fw}: <span className="text-accent-green">{ctrl}</span>
                        </span>
                      ))}
                    </div>
                  </section>
                )}

                <section>
                  <div className="label mb-1 text-accent-green">Remediation</div>
                  <p className="font-body text-sm text-text-secondary leading-relaxed whitespace-pre-line border-l-2 border-accent-muted pl-3">
                    {selected.remediation}
                  </p>
                </section>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
