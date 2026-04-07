import { useState } from 'preact/hooks'
import { csrfFetch } from '../api'

function formatCallResult(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value)
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function Call() {
  const [kind, setKind] = useState('')
  const [spec, setSpec] = useState('')
  const [status, setStatus] = useState('')
  const [result, setResult] = useState('Result will appear here.')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const trimmedKind = kind.trim()
    if (!trimmedKind) {
      setStatus('Kind is required.')
      setResult('No request executed.')
      return
    }

    let parsedSpec: unknown = null
    const trimmedSpec = spec.trim()
    if (trimmedSpec) {
      try {
        parsedSpec = JSON.parse(trimmedSpec)
      } catch (e) {
        setStatus(`Spec JSON invalid: ${(e as Error).message}`)
        setResult(trimmedSpec)
        return
      }
    }

    setLoading(true)
    setStatus('Calling...')

    try {
      const resp = await csrfFetch('/api/v1/call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: trimmedKind, spec: parsedSpec })
      })

      let payload: any
      const raw = await resp.text()
      try { payload = JSON.parse(raw) } catch { /* not JSON */ }

      if (!resp.ok) {
        const errorMsg = payload?.error ?? resp.statusText ?? 'Request failed'
        setStatus(`Request failed: ${errorMsg}`)
        setResult(payload ? JSON.stringify(payload, null, 2) : raw || 'No response body')
        return
      }

      if (!payload) {
        setStatus('Call succeeded (empty response).')
        setResult(raw || 'No response body')
        return
      }

      if (payload.success) {
        setStatus('Call succeeded.')
        setResult(payload.result !== undefined ? formatCallResult(payload.result) : 'Result: undefined')
      } else {
        const message = payload.error ?? 'Call failed.'
        setStatus(`Call failed: ${message}`)
        setResult(JSON.stringify(payload, null, 2))
      }
    } catch (e) {
      setStatus((e as Error).message ?? 'Unexpected error')
      setResult('Request failed.')
    } finally {
      setLoading(false)
    }
  }

  function handleClear() {
    setKind('')
    setSpec('')
    setResult('Result will appear here.')
    setStatus('Cleared.')
  }

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 shrink-0">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Call</h1>
        <p class="text-sm text-neutral-500 mt-0.5">Invoke a service kind with a spec</p>
      </div>
      <div class="flex-1 overflow-auto p-6">
        <form onSubmit={handleSubmit} class="flex flex-col gap-4 max-w-2xl">
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium text-neutral-700 dark:text-neutral-300">Kind</label>
            <input
              type="text"
              value={kind}
              onInput={(e) => setKind((e.target as HTMLInputElement).value)}
              placeholder="e.g. ProxyPass"
              class="px-3 py-2 border border-neutral-300 dark:border-neutral-600 rounded bg-white dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100 text-sm font-mono"
            />
          </div>
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium text-neutral-700 dark:text-neutral-300">Spec (JSON)</label>
            <textarea
              value={spec}
              onInput={(e) => setSpec((e.target as HTMLTextAreaElement).value)}
              placeholder='{"key": "value"}'
              rows={6}
              class="px-3 py-2 border border-neutral-300 dark:border-neutral-600 rounded bg-white dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100 text-sm font-mono resize-y"
            />
          </div>
          <div class="flex gap-2">
            <button
              type="submit"
              disabled={loading}
              class="px-4 py-2 rounded bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 text-sm"
            >
              {loading ? 'Calling...' : 'Call'}
            </button>
            <button
              type="button"
              onClick={handleClear}
              class="px-4 py-2 rounded bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-200 text-sm"
            >
              Clear
            </button>
          </div>
          {status && (
            <div class="text-xs text-neutral-500 font-mono">{status}</div>
          )}
          <div class="flex flex-col gap-1">
            <div class="text-sm font-medium text-neutral-700 dark:text-neutral-300">Result</div>
            <pre class="p-3 rounded bg-neutral-100 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 text-xs font-mono overflow-x-auto whitespace-pre-wrap text-neutral-800 dark:text-neutral-200 min-h-[80px]">
              {result}
            </pre>
          </div>
        </form>
      </div>
    </div>
  )
}
