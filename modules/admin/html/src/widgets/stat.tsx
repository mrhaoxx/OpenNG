import { useState, useEffect, useRef } from 'preact/hooks'
import { resolveSource } from '../api'

interface StatWidgetProps {
  source?: string
  label?: string
  value?: string
  unit?: string
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

export function StatWidget({ source, label, value: staticValue, unit, poll, instanceName }: StatWidgetProps) {
  const [data, setData] = useState<any>(staticValue ?? null)
  const timerRef = useRef<number>(0)

  useEffect(() => {
    if (!source) return
    const url = resolveSource(source, instanceName)

    async function fetchData() {
      try {
        const resp = await fetch(url)
        if (!resp.ok) return
        const text = await resp.text()
        try { setData(JSON.parse(text)) } catch { setData(text) }
      } catch { /* ignore */ }
    }

    fetchData()
    const ms = parsePollMs(poll)
    if (ms > 0) {
      timerRef.current = window.setInterval(fetchData, ms)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [source, instanceName, poll])

  const displayValue = typeof data === 'object' && data !== null
    ? JSON.stringify(data)
    : String(data ?? '—')

  return (
    <div class="p-4 border border-neutral-200 dark:border-neutral-700 rounded-lg">
      {label && <div class="text-xs text-neutral-500 dark:text-neutral-400 uppercase tracking-wider mb-1">{label}</div>}
      <div class="text-2xl font-semibold text-neutral-900 dark:text-neutral-100">
        {displayValue}
        {unit && <span class="text-sm text-neutral-500 ml-1">{unit}</span>}
      </div>
    </div>
  )
}
