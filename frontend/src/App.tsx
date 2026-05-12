import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
import { lazy, Suspense } from 'react'
import { Spinner } from './components/ui'

const Dashboard   = lazy(() => import('./pages/Dashboard'))
const Findings    = lazy(() => import('./pages/Findings'))
const Compliance  = lazy(() => import('./pages/Compliance'))
const Assets      = lazy(() => import('./pages/Assets'))
const Scans       = lazy(() => import('./pages/Scans'))
const IaC         = lazy(() => import('./pages/IaC'))
const AttackPaths = lazy(() => import('./pages/AttackPaths'))
const Chat        = lazy(() => import('./pages/Chat'))

function Loading() {
  return (
    <div className="flex items-center justify-center h-full gap-3">
      <Spinner size={18} />
      <span className="font-mono text-xs text-text-secondary">Loading…</span>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index          element={<Suspense fallback={<Loading />}><Dashboard /></Suspense>} />
          <Route path="findings"     element={<Suspense fallback={<Loading />}><Findings /></Suspense>} />
          <Route path="compliance"   element={<Suspense fallback={<Loading />}><Compliance /></Suspense>} />
          <Route path="assets"       element={<Suspense fallback={<Loading />}><Assets /></Suspense>} />
          <Route path="scans"        element={<Suspense fallback={<Loading />}><Scans /></Suspense>} />
          <Route path="iac"          element={<Suspense fallback={<Loading />}><IaC /></Suspense>} />
          <Route path="attack-paths" element={<Suspense fallback={<Loading />}><AttackPaths /></Suspense>} />
          <Route path="chat"         element={<Suspense fallback={<Loading />}><Chat /></Suspense>} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
