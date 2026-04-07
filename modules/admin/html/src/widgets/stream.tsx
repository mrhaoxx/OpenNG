import { useState, useEffect, useRef } from 'preact/hooks'
import { resolveSource } from '../api'

interface StreamWidgetProps {
  source: string
  maxLines?: number
  instanceName: string
}

export function StreamWidget({ source, maxLines = 200, instanceName }: StreamWidgetProps) {
  const [lines, setLines] = useState<string[]>([])
  const [connected, setConnected] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const url = resolveSource(source, instanceName)
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (ev) => {
      setLines(prev => {
        const next = [...prev, ev.data]
        return next.length > maxLines ? next.slice(next.length - maxLines) : next
      })
    }

    return () => { es.close() }
  }, [source, instanceName])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div class="flex flex-col h-64 border border-neutral-200 dark:border-neutral-700 rounded overflow-hidden">
      <div class="flex items-center gap-2 px-2 py-1 bg-neutral-100 dark:bg-neutral-800 border-b border-neutral-200 dark:border-neutral-700 shrink-0">
        <span class={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
        <span class="text-xs text-neutral-500">{connected ? 'Connected' : 'Disconnected'}</span>
      </div>
      <div class="flex-1 overflow-y-auto p-2 font-mono text-xs bg-neutral-950 text-neutral-200">
        {lines.map((line, i) => <div key={i}>{line}</div>)}
        <div ref={endRef} />
      </div>
    </div>
  )
}
