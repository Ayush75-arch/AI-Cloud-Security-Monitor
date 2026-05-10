import { NavLink, Outlet, useLocation } from 'react-router-dom'
import clsx from 'clsx'

const NAV = [
  { to: '/',           label: 'Overview',   icon: '◈' },
  { to: '/findings',   label: 'Findings',   icon: '⬡' },
  { to: '/compliance', label: 'Compliance', icon: '◻' },
  { to: '/assets',     label: 'Assets',     icon: '◇' },
  { to: '/scans',      label: 'Scans',      icon: '▷' },
]

export function AppLayout() {
  return (
    <div className="flex h-screen overflow-hidden bg-bg-primary">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-bg-secondary border-r border-bg-border flex flex-col">
        {/* Logo */}
        <div className="px-5 py-5 border-b border-bg-border">
          <div className="flex items-center gap-2">
            <span className="text-accent-green text-xl">◈</span>
            <div>
              <div className="font-display text-sm font-bold text-text-primary tracking-tight">CloudGuard</div>
              <div className="font-mono text-2xs text-accent-green tracking-widest uppercase">AI · CSPM</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 px-3 space-y-0.5">
          {NAV.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 font-mono text-xs uppercase tracking-widest transition-colors',
                  isActive
                    ? 'text-accent-green bg-accent-muted border-l-2 border-accent-green'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover border-l-2 border-transparent',
                )
              }
            >
              <span className="text-base leading-none">{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-bg-border">
          <div className="font-mono text-2xs text-text-muted uppercase tracking-widest">v1.0.0</div>
          <div className="font-mono text-2xs text-text-muted mt-0.5">AWS · us-east-1</div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
