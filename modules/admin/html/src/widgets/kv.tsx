import { useState, useEffect, useRef } from 'preact/hooks'
import { resolveSource } from '../api'

interface KVWidgetProps {
  source?: string
  data?: Record<string, any>
  poll?: string
  instanceName: string
}

function parsePollMs(poll: string | undefined): number {
  if (!poll) return 0
  const m = poll.match(/^(\d+)(ms|s|m)?$/)
  if (!m) return 0
  const n = parseInt(m[1], 10)
  const unit = m[2] || 'ms'
  if (unit === 's') return n * 1000
  if (unit === 'm') return n * 60000
  return n
}

export function KVWidget({ source, data: staticData, poll, instanceName }: KVWidgetProps) {
  const [data, setData] = useState<Record<string, any>>(staticData || {})
  const timerRef = useRef<number>(0)

  useEffect(() => {
    if (!source) return
    const url = resolveSource(source, instanceName)

    async function fetchData() {
      try {
        const resp = await fetch(url)
        if (!resp.ok) return
        const json = await resp.json()
        setData(json)
      } catch { /* ignore */ }
    }

    fetchData()
    const ms = parsePollMs(poll)
    if (ms > 0) {
      timerRef.current = window.setInterval(fetchData, ms)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [source, instanceName, poll])

  return (
    <dl class="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-sm">
      {Object.entries(data).map(([k, v]) => (
        <>
          <dt class="font-medium text-neutral-500 dark:text-neutral-400 whitespace-nowrap">{k}</dt>
          <dd class="text-neutral-900 dark:text-neutral-100 font-mono text-xs break-all">
            {typeof v === 'object' ? JSON.stringify(v) : String(v ?? '')}
          </dd>
        </>
      ))}
    </dl>
  )
}
