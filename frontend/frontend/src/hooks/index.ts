import { useEffect, useRef, useState, useCallback } from 'react'

/** Polls an async fn every `interval` ms while `active` is true. */
export function usePoll(fn: () => Promise<void>, interval: number, active: boolean) {
  useEffect(() => {
    if (!active) return
    const id = setInterval(fn, interval)
    return () => clearInterval(id)
  }, [fn, interval, active])
}

/** Simple async state helper. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const run = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fn()
      setData(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => { run() }, [run])

  return { data, loading, error, refetch: run }
}
