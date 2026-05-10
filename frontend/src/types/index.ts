// ── Enums ─────────────────────────────────────────────────────────────────────

export type Severity        = 'critical' | 'high' | 'medium' | 'low'
export type ScanStatus      = 'pending' | 'running' | 'completed' | 'failed'
export type FindingStatus   = 'open' | 'suppressed' | 'resolved'
export type AssetType       = 's3_bucket' | 'iam_role' | 'iam_policy' | 'iam_user' | 'ec2_instance' | 'security_group' | 'vpc' | 'subnet'
export type ComplianceFrame = 'CIS' | 'NIST' | 'PCI-DSS'

// ── API Envelope ──────────────────────────────────────────────────────────────

export interface APIResponse<T> {
  data: T
  meta: Record<string, unknown>
  errors: { code: string; message: string }[]
}

export interface PaginationMeta {
  page: number
  limit: number
  total: number
  total_pages: number
}

// ── Scan ──────────────────────────────────────────────────────────────────────

export interface Scan {
  id: string
  status: ScanStatus
  account_id: string
  region: string
  services: string[]
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  started_at: string | null
  completed_at: string | null
  created_at: string
  error_message?: string | null
  triggered_by?: string | null
}

export interface ScanCreateRequest {
  account_id: string
  region: string
  services: string[]
  triggered_by?: string
}

// ── Asset ─────────────────────────────────────────────────────────────────────

export interface Asset {
  id: string
  scan_id: string
  asset_type: AssetType
  asset_id: string
  asset_name: string
  region: string
  created_at: string
}

// ── Finding ───────────────────────────────────────────────────────────────────

export interface Finding {
  id: string
  scan_id: string
  asset_id: string
  rule_id: string
  title: string
  description: string
  severity: Severity
  status: FindingStatus
  compliance_mappings: Record<string, string>
  ai_explanation: string | null
  ai_attack_scenario: string | null
  ai_remediation: string | null
  created_at: string
  updated_at: string
  asset?: Asset
}

// ── Compliance ────────────────────────────────────────────────────────────────

export interface ComplianceResult {
  id: string
  scan_id: string
  framework: ComplianceFrame
  score: number
  passed_controls: number
  failed_controls: number
  control_details: Record<string, { status: 'PASS' | 'FAIL'; rule_id?: string; title?: string; severity?: string }>
  computed_at: string
}

export interface ComplianceSummary {
  overall_score: number
  frameworks: ComplianceResult[]
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export interface SeverityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
}

export interface DashboardStats {
  total_findings: number
  open_findings: number
  severity_breakdown: SeverityBreakdown
  total_assets: number
  last_scan_at: string | null
  compliance_scores: Record<string, number>
  risk_score: number
}
