import { useEffect, useState, useRef } from 'react'
import { resolveSource } from '@/lib/api'

function parsePoll(s: unknown): number {
  if (typeof s !== 'string') return 0
  const m = s.match(/^(\d+)(ms|s|m)?$/)
  if (!m) return 0
  const n = parseInt(m[1])
  if (m[2] === 'ms') return n
  if (m[2] === 'm') return n * 60000
  return n * 1000
}

function formatValue(val: unknown, unit?: string): string {
  if (val == null) return '–'
  if (unit === 'bytes' && typeof val === 'number') {
    if (val < 1024) return `${val} B`
    if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB`
    if (val < 1024 * 1024 * 1024) return `${(val / 1024 / 1024).toFixed(1)} MB`
    return `${(val / 1024 / 1024 / 1024).toFixed(2)} GB`
  }
  if (typeof val === 'number') {
    return Number.isInteger(val) ? String(val) : val.toFixed(2)
  }
  return String(val)
}

export default function StatWidget(props: Record<string, unknown> & { instanceName: string }) {
  const { label, source, field, unit, poll, instanceName } = props as {
    label?: string; source?: string; field?: string; unit?: string; poll?: string; instanceName: string
  }
  const [value, setValue] = useState<unknown>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!source) return

    const url = resolveSource(source, instanceName)
    const doFetch = () => {
      fetch(url)
        .then(r => r.json())
        .then(data => {
          if (field && typeof data === 'object' && data !== null) {
            setValue((data as Record<string, unknown>)[field])
          } else {
            setValue(data)
          }
        })
        .catch(() => {})
    }

    doFetch()
    const interval = parsePoll(poll)
    if (interval > 0) {
      timerRef.current = setInterval(doFetch, interval)
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [source, field, poll, instanceName])

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 px-3 py-2 min-w-0">
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider truncate">{String(label ?? '')}</p>
      <p className="text-lg font-semibold font-mono mt-0.5">{formatValue(value, unit)}</p>
    </div>
  )
}
