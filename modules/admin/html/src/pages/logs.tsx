import { useEffect, useRef, useState } from 'preact/hooks'

const MAX_LINES = 1000

export function Logs() {
  const [lines, setLines] = useState<string[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)
  const pausedRef = useRef(false)

  pausedRef.current = paused

  useEffect(() => {
    const es = new EventSource('/logs')

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (ev) => {
      setLines(prev => {
        const next = [...prev, ev.data]
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
      })
    }

    return () => es.close()
  }, [])

  useEffect(() => {
    if (!paused) {
      endRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, paused])

  function clearLogs() {
    setLines([])
  }

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 shrink-0 flex items-center gap-4">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Logs</h1>
        <div class="flex items-center gap-2 ml-2">
          <span class={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span class="text-xs text-neutral-500">{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
        <div class="ml-auto flex gap-2">
          <button
            onClick={() => setPaused(p => !p)}
            class={`px-3 py-1.5 rounded text-sm ${paused ? 'bg-yellow-500 text-white' : 'bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-200'}`}
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={clearLogs}
            class="px-3 py-1.5 rounded bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-200 text-sm"
          >
            Clear
          </button>
        </div>
      </div>
      <div class="flex-1 overflow-y-auto p-4 font-mono text-xs bg-neutral-950 text-neutral-200">
        {lines.map((line, i) => (
          <div key={i} class="leading-relaxed whitespace-pre-wrap break-all">{line}</div>
        ))}
        {lines.length === 0 && (
          <div class="text-neutral-500">Waiting for log events...</div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}
