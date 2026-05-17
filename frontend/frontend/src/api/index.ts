import { apiClient } from './client'
import type {
  APIResponse,
  ComplianceSummary,
  DashboardStats,
  Finding,
  PaginationMeta,
  Scan,
  ScanCreateRequest,
  Asset,
} from '../types'

// ── Dashboard ─────────────────────────────────────────────────────────────────

export const getDashboardStats = async (): Promise<DashboardStats> => {
  const res = await apiClient.get<APIResponse<DashboardStats>>('/dashboard/stats')
  return res.data.data
}

// ── Scans ─────────────────────────────────────────────────────────────────────

export const createScan = async (payload: ScanCreateRequest): Promise<Scan> => {
  const res = await apiClient.post<APIResponse<Scan>>('/scans', payload)
  return res.data.data
}

export const listScans = async (
  page = 1,
  limit = 20,
): Promise<{ scans: Scan[]; meta: PaginationMeta }> => {
  const res = await apiClient.get<APIResponse<Scan[]>>('/scans', { params: { page, limit } })
  return { scans: res.data.data, meta: res.data.meta as unknown as PaginationMeta }
}

export const getScan = async (id: string): Promise<Scan> => {
  const res = await apiClient.get<APIResponse<Scan>>(`/scans/${id}`)
  return res.data.data
}

export const getScanFindings = async (
  scanId: string,
  params: { severity?: string; status?: string; page?: number; limit?: number } = {},
): Promise<{ findings: Finding[]; meta: PaginationMeta }> => {
  const res = await apiClient.get<APIResponse<Finding[]>>(`/scans/${scanId}/findings`, { params })
  return { findings: res.data.data, meta: res.data.meta as unknown as PaginationMeta }
}

// ── Findings ──────────────────────────────────────────────────────────────────

export const listFindings = async (params: {
  severity?: string
  status?: string
  rule_id?: string
  page?: number
  limit?: number
} = {}): Promise<{ findings: Finding[]; meta: PaginationMeta }> => {
  const res = await apiClient.get<APIResponse<Finding[]>>('/findings', { params })
  return { findings: res.data.data, meta: res.data.meta as unknown as PaginationMeta }
}

export const getFinding = async (id: string): Promise<Finding> => {
  const res = await apiClient.get<APIResponse<Finding>>(`/findings/${id}`)
  return res.data.data
}

export const suppressFinding = async (id: string, reason: string): Promise<Finding> => {
  const res = await apiClient.patch<APIResponse<Finding>>(`/findings/${id}/suppress`, { reason })
  return res.data.data
}

// ── Compliance ────────────────────────────────────────────────────────────────

export const getCompliance = async (scanId?: string): Promise<ComplianceSummary> => {
  const res = await apiClient.get<APIResponse<ComplianceSummary>>('/compliance', {
    params: scanId ? { scan_id: scanId } : {},
  })
  return res.data.data
}

// ── Assets ────────────────────────────────────────────────────────────────────

export const listAssets = async (params: {
  scan_id?: string
  asset_type?: string
  page?: number
  limit?: number
} = {}): Promise<{ assets: Asset[]; meta: PaginationMeta }> => {
  const res = await apiClient.get<APIResponse<Asset[]>>('/assets', { params })
  return { assets: res.data.data, meta: res.data.meta as unknown as PaginationMeta }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const login = async (username: string, password: string): Promise<string> => {
  const res = await apiClient.post('/auth/login', { username, password })
  const token: string = res.data.data.access_token
  return token
}

export const getMe = async () => {
  const res = await apiClient.get('/auth/me')
  return res.data.data
}
