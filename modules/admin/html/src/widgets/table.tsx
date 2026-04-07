import { useState, useEffect, useRef } from 'preact/hooks'
import { resolveSource } from '../api'
import type { ColumnDef } from './types'

interface TableWidgetProps {
  source: string
  poll?: string
  columns?: ColumnDef[]
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

function padZero(v: number): string { return v.toString().padStart(2, '0') }
function formatElapsed(ms: number): string {
  const sec = Math.floor(ms / 1000)
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return `${padZero(h)}:${padZero(m)}:${padZero(s)}`
}

function formatCellValue(value: any, col: ColumnDef | undefined): string {
  if (value === null || value === undefined) return ''
  if (col?.type === 'bytes') {
    const n = Number(value)
    if (n < 1024) return `${n} B`
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / 1048576).toFixed(2)} MB`
  }
  if (col?.type === 'elapsed') {
    const start = new Date(String(value)).getTime()
    return formatElapsed(Date.now() - start)
  }
  return String(value)
}

function getColorClass(value: any, col: ColumnDef | undefined): string {
  if (!col?.colorMap) return ''
  return col.colorMap[String(value)] || ''
}

export function TableWidget({ source, poll, columns, instanceName }: TableWidgetProps) {
  const [rows, setRows] = useState<Record<string, any>[]>([])
  const [sortKey, setSortKey] = useState<string>('')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [error, setError] = useState<string | null>(null)
  const timerRef = useRef<number>(0)

  const url = resolveSource(source, instanceName)

  async function fetchData() {
    try {
      const resp = await fetch(url)
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      if (Array.isArray(data)) {
        setRows(data)
      } else if (data && typeof data === 'object') {
        setRows(Object.entries(data).map(([id, v]: [string, any]) => ({ id, ...(v || {}) })))
      }
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  useEffect(() => {
    fetchData()
    const ms = parsePollMs(poll)
    if (ms > 0) {
      timerRef.current = window.setInterval(fetchData, ms)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [source, instanceName, poll])

  // Derive columns from data if not provided
  const cols: ColumnDef[] = columns && columns.length > 0
    ? columns
    : rows.length > 0
      ? Object.keys(rows[0]).map(k => ({ field: k, label: k, type: 'text', sortable: true }))
      : []

  const sorted = [...rows].sort((a, b) => {
    if (!sortKey) return 0
    const av = a[sortKey]
    const bv = b[sortKey]
    const cmp = typeof av === 'number' && typeof bv === 'number'
      ? av - bv
      : String(av ?? '').localeCompare(String(bv ?? ''))
    return sortDir === 'asc' ? cmp : -cmp
  })

  function handleSort(key: string) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  if (error) {
    return <div class="text-xs text-red-500 p-2">Error: {error}</div>
  }

  return (
    <div class="overflow-x-auto">
      <table class="w-full text-sm text-left border-collapse">
        <thead>
          <tr class="border-b border-neutral-200 dark:border-neutral-700">
            {cols.map(col => (
              <th
                key={col.field}
                class={`px-3 py-2 font-medium text-neutral-500 dark:text-neutral-400 text-xs uppercase tracking-wider whitespace-nowrap ${col.sortable !== false ? 'cursor-pointer select-none hover:text-neutral-800 dark:hover:text-neutral-200' : ''}`}
                onClick={() => col.sortable !== false && handleSort(col.field)}
              >
                {col.label}
                {sortKey === col.field && (
                  <span class="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr key={i} class="border-b border-neutral-100 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/40">
              {cols.map(col => {
                const colorClass = getColorClass(row[col.field], col)
                return (
                  <td key={col.field} class={`px-3 py-2 font-mono text-xs ${colorClass}`}>
                    {formatCellValue(row[col.field], col)}
                  </td>
                )
              })}
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={cols.length} class="px-3 py-4 text-center text-neutral-400 text-xs">No data</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
