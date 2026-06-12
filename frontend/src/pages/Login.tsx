import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api'
import { setAuthToken } from '../api/client'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async () => {
    if (!username || !password) return
    setLoading(true)
    setError('')
    try {
      const token = await login(username, password)
      setAuthToken(token)
      navigate('/')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center h-screen bg-bg-primary">
      <div className="w-80 border border-bg-border p-8 space-y-6">
        <div>
          <div className="font-mono text-2xs text-accent-green uppercase tracking-widest mb-1">CloudGuard-AI</div>
          <h1 className="font-display text-xl font-bold text-text-primary">Sign in</h1>
        </div>

        <div className="space-y-3">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
            placeholder="Username"
            className="w-full bg-bg-secondary border border-bg-border px-3 py-2 font-mono text-xs text-text-primary focus:outline-none focus:border-accent-green"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
            placeholder="Password"
            className="w-full bg-bg-secondary border border-bg-border px-3 py-2 font-mono text-xs text-text-primary focus:outline-none focus:border-accent-green"
          />
        </div>

        {error && (
          <div className="font-mono text-xs text-accent-red">{error}</div>
        )}

        <button
          onClick={handleSubmit}
          disabled={loading || !username || !password}
          className="btn-primary w-full disabled:opacity-40"
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>

        <div className="font-mono text-2xs text-text-muted">
          Demo: admin / cloudguard123
        </div>
      </div>
    </div>
  )
}
