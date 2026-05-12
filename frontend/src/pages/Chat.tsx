import { useState, useRef, useEffect } from 'react'
import { apiClient } from '../api/client'
import { Spinner } from '../components/ui'

interface Message {
  role: 'user' | 'assistant'
  content: string
  suggestions?: string[]
}

const STARTERS = [
  "Why is an open S3 bucket dangerous?",
  "How would an attacker exploit IAM wildcard permissions?",
  "What does CIS Benchmark 1.16 mean?",
  "Explain VPC flow logs and why they matter",
  "What is the blast radius of a compromised admin IAM user?",
  "How do I implement least-privilege IAM policies?",
]

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "I'm CloudGuard-AI, your cloud security analyst. Ask me anything about misconfigurations, attack techniques, compliance requirements, or remediation steps. I have deep knowledge of AWS security, IAM, S3, VPC, and compliance frameworks like CIS, NIST, PCI-DSS, ISO 27001, and GDPR.",
      suggestions: STARTERS.slice(0, 3),
    },
  ])
  const [input, setInput]       = useState('')
  const [loading, setLoading]   = useState(false)
  const [aiConfigured, setAiConfigured] = useState<boolean | null>(null)
  const bottomRef               = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let ignore = false

    apiClient.get('/health')
      .then((res) => {
        if (ignore) return
        const configured = Boolean(res.data?.ai_configured)
        setAiConfigured(configured)
        if (configured) {
          localStorage.setItem('groq_configured', 'true')
        } else {
          localStorage.removeItem('groq_configured')
        }
      })
      .catch(() => {
        if (!ignore) setAiConfigured(null)
      })

    return () => {
      ignore = true
    }
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async (text: string) => {
    if (!text.trim() || loading) return
    const userMsg: Message = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const history = messages
        .filter(m => m.role !== 'assistant' || messages.indexOf(m) > 0)
        .map(m => ({ role: m.role, content: m.content }))

      const res = await apiClient.post('/chat', {
        message: text,
        history,
      })
      const data = res.data.data
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.message,
        suggestions: data.suggested_questions,
      }])
    } catch {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Failed to get a response. Check that the backend is running.',
      }])
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send(input)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
        <div>
          <h1 className="font-display text-lg font-bold text-text-primary">AI Security Copilot</h1>
          <p className="font-mono text-2xs text-text-muted mt-0.5 uppercase tracking-widest">
            Natural language cloud security Q&A
          </p>
        </div>
        <div className="font-mono text-2xs text-accent-green flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse-green inline-block" />
          CloudGuard-AI
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-auto px-6 py-4 space-y-4">
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[80%] space-y-3`}>
              {/* Role label */}
              <div className={`font-mono text-2xs uppercase tracking-widest ${
                msg.role === 'user' ? 'text-right text-text-muted' : 'text-accent-green'
              }`}>
                {msg.role === 'user' ? 'You' : '◈ CloudGuard-AI'}
              </div>

              {/* Bubble */}
              <div className={`px-4 py-3 font-body text-sm leading-relaxed ${
                msg.role === 'user'
                  ? 'bg-bg-panel border border-bg-border text-text-primary ml-auto'
                  : 'bg-bg-secondary border border-bg-border text-text-secondary border-l-2 border-l-accent-green'
              }`}>
                {msg.content}
              </div>

              {/* Suggested follow-ups */}
              {msg.suggestions && msg.suggestions.length > 0 && i === messages.length - 1 && (
                <div className="space-y-1">
                  <div className="font-mono text-2xs text-text-muted uppercase tracking-widest">Suggested questions</div>
                  {msg.suggestions.map((q, qi) => (
                    <button
                      key={qi}
                      onClick={() => send(q)}
                      disabled={loading}
                      className="block w-full text-left font-mono text-xs text-text-secondary border border-bg-border px-3 py-2 hover:border-accent-green hover:text-accent-green transition-colors disabled:opacity-40"
                    >
                      → {q}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}

        {/* Loading indicator */}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-bg-secondary border border-bg-border border-l-2 border-l-accent-green px-4 py-3 flex items-center gap-2">
              <Spinner size={12} />
              <span className="font-mono text-xs text-text-muted">Analyzing…</span>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Starter prompts (only on first message) */}
      {messages.length === 1 && (
        <div className="px-6 pb-3 grid grid-cols-2 gap-2">
          {STARTERS.map((s, i) => (
            <button
              key={i}
              onClick={() => send(s)}
              className="font-mono text-xs text-text-secondary border border-bg-border px-3 py-2 text-left hover:border-accent-green hover:text-accent-green transition-colors"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="px-6 py-4 border-t border-bg-border">
        <div className="flex gap-3">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Ask about any finding, attack technique, or compliance requirement…"
            rows={2}
            className="flex-1 bg-bg-secondary border border-bg-border px-4 py-2 font-mono text-xs text-text-primary focus:outline-none focus:border-accent-green resize-none leading-relaxed"
          />
          <button
            onClick={() => send(input)}
            disabled={loading || !input.trim()}
            className="btn-primary self-end disabled:opacity-40 px-6"
          >
            {loading ? <Spinner size={12} /> : '↑'}
          </button>
        </div>
        <div className="font-mono text-2xs text-text-muted mt-1">
          Enter to send · Shift+Enter for newline
          {aiConfigured === false && (
            <span className="ml-3 text-accent-yellow">
              · No GROQ key — using built-in responses
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
