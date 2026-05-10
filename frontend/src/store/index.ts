import { create } from 'zustand'
import type { DashboardStats, Finding, Scan } from '../types'

// ── Scan Store ────────────────────────────────────────────────────────────────

interface ScanStore {
  scans: Scan[]
  activeScan: Scan | null
  isScanning: boolean
  setScans: (scans: Scan[]) => void
  setActiveScan: (scan: Scan | null) => void
  setIsScanning: (v: boolean) => void
  updateScan: (scan: Scan) => void
}

export const useScanStore = create<ScanStore>((set) => ({
  scans: [],
  activeScan: null,
  isScanning: false,
  setScans: (scans) => set({ scans }),
  setActiveScan: (activeScan) => set({ activeScan }),
  setIsScanning: (isScanning) => set({ isScanning }),
  updateScan: (updated) =>
    set((s) => ({
      scans: s.scans.map((sc) => (sc.id === updated.id ? updated : sc)),
      activeScan: s.activeScan?.id === updated.id ? updated : s.activeScan,
    })),
}))

// ── Finding Store ─────────────────────────────────────────────────────────────

interface FindingStore {
  findings: Finding[]
  selectedFinding: Finding | null
  severityFilter: string | null
  statusFilter: string | null
  setFindings: (findings: Finding[]) => void
  setSelectedFinding: (f: Finding | null) => void
  setSeverityFilter: (s: string | null) => void
  setStatusFilter: (s: string | null) => void
}

export const useFindingStore = create<FindingStore>((set) => ({
  findings: [],
  selectedFinding: null,
  severityFilter: null,
  statusFilter: null,
  setFindings: (findings) => set({ findings }),
  setSelectedFinding: (selectedFinding) => set({ selectedFinding }),
  setSeverityFilter: (severityFilter) => set({ severityFilter }),
  setStatusFilter: (statusFilter) => set({ statusFilter }),
}))

// ── Dashboard Store ───────────────────────────────────────────────────────────

interface DashboardStore {
  stats: DashboardStats | null
  setStats: (stats: DashboardStats) => void
}

export const useDashboardStore = create<DashboardStore>((set) => ({
  stats: null,
  setStats: (stats) => set({ stats }),
}))
