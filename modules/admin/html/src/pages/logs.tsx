import { useEffect, useRef, useState, useCallback } from 'react'
import { Search, Trash2, ArrowDown } from 'lucide-react'

interface LogEntry {
  id: number
  raw: string
  parsed: Record<string, unknown> | null
  level: string
  time: string
  type: string
  message: string
}

const LEVEL_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  trace: { bg: 'bg-neutral-800', text: 'text-neutral-400', label: 'TRC' },
  debug: { bg: 'bg-neutral-800', text: 'text-neutral-300', label: 'DBG' },
  info:  { bg: 'bg-blue-500/10', text: 'text-blue-400', label: 'INF' },
  warn:  { bg: 'bg-yellow-500/10', text: 'text-yellow-400', label: 'WRN' },
  error: { bg: 'bg-red-500/10', text: 'text-red-400', label: 'ERR' },
  fatal: { bg: 'bg-red-500/20', text: 'text-red-300', label: 'FTL' },
  panic: { bg: 'bg-red-500/30', text: 'text-red-200', label: 'PNC' },
}

const HIDDEN_KEYS = new Set(['level', 'time', 'message', 'type'])

function parseLogLine(line: string, id: number): LogEntry | null {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith('#')) return null
  try {
    const obj = JSON.parse(trimmed)
    return {
      id,
      raw: trimmed,
      parsed: obj,
      level: obj.level ?? '',
      time: obj.time ?? '',
      type: obj.type ?? '',
      message: obj.message ?? '',
    }
  } catch {
    return { id, raw: trimmed, parsed: null, level: '', time: '', type: '', message: trimmed }
  }
}

function formatTime(t: string): string {
  if (!t) return ''
  try {
    const d = new Date(t)
    return d.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })
  } catch { return t }
}

function formatValue(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return String(v)
    return v.toFixed(2)
  }
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

const MAX_ENTRIES = 2000

export default function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [filter, setFilter] = useState('')
  const [levelFilter, setLevelFilter] = useState<Set<string>>(new Set())
  const [typeFilter, setTypeFilter] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const [connected, setConnected] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const idRef = useRef(0)

  // Connect to SSE stream
  useEffect(() => {
    const abortController = new AbortController()
    let buffer = ''

    async function connect() {
      try {
        const resp = await fetch('/logs', { signal: abortController.signal })
        if (!resp.body) return
        setConnected(true)
        const reader = resp.body.getReader()
        const decoder = new TextDecoder()

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop() ?? ''

          const newEntries: LogEntry[] = []
          for (const line of lines) {
            const entry = parseLogLine(line, idRef.current++)
            if (entry) newEntries.push(entry)
          }
          if (newEntries.length > 0) {
            setEntries(prev => {
              const combined = [...prev, ...newEntries]
              return combined.length > MAX_ENTRIES ? combined.slice(-MAX_ENTRIES) : combined
            })
          }
        }
      } catch (e) {
        if ((e as Error).name !== 'AbortError') {
          setConnected(false)
          // Reconnect after 2s
          setTimeout(connect, 2000)
        }
      }
    }

    connect()
    return () => abortController.abort()
  }, [])

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [entries, autoScroll])

  // Detect manual scroll
  const onScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50
    setAutoScroll(atBottom)
  }, [])

  const clear = () => setEntries([])

  // Collect all types for filter dropdown
  const allTypes = [...new Set(entries.map(e => e.type).filter(Boolean))].sort()

  // Filter entries
  const lowerFilter = filter.toLowerCase()
  const filtered = entries.filter(e => {
    if (levelFilter.size > 0 && !levelFilter.has(e.level)) return false
    if (typeFilter && e.type !== typeFilter) return false
    if (lowerFilter && !e.raw.toLowerCase().includes(lowerFilter)) return false
    return true
  })

  const toggleLevel = (level: string) => {
    setLevelFilter(prev => {
      const next = new Set(prev)
      if (next.has(level)) next.delete(level)
      else next.add(level)
      return next
    })
  }

  return (
    <div className="h-full flex flex-col bg-background">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-b border-border bg-card">
        {/* Connection indicator */}
        <div className={`w-2 h-2 rounded-full shrink-0 ${connected ? 'bg-green-500' : 'bg-red-500'}`} title={connected ? 'Connected' : 'Disconnected'} />

        {/* Level filter buttons */}
        <div className="flex gap-0.5">
          {Object.entries(LEVEL_COLORS).map(([level, { text, label }]) => (
            <button
              key={level}
              onClick={() => toggleLevel(level)}
              className={`px-1.5 py-0.5 text-[10px] font-mono rounded transition-colors ${
                levelFilter.size === 0 || levelFilter.has(level)
                  ? `${text} bg-neutral-800`
                  : 'text-neutral-600 bg-neutral-900'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Type filter */}
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="bg-neutral-800 border border-neutral-700 rounded px-1.5 py-0.5 text-[11px] text-neutral-300"
        >
          <option value="">all types</option>
          {allTypes.map(t => <option key={t} value={t}>{t}</option>)}
        </select>

        {/* Text filter */}
        <div className="flex items-center gap-1 flex-1 max-w-xs bg-neutral-800 border border-neutral-700 rounded px-2 py-0.5">
          <Search className="size-3 text-neutral-500 shrink-0" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="filter..."
            className="bg-transparent text-xs text-foreground outline-none w-full"
          />
        </div>

        <span className="text-[10px] text-neutral-500 ml-auto">{filtered.length} / {entries.length}</span>

        <button onClick={clear} className="p-1 text-neutral-500 hover:text-neutral-300" title="Clear">
          <Trash2 className="size-3.5" />
        </button>
        <button
          onClick={() => { setAutoScroll(true); containerRef.current?.scrollTo({ top: containerRef.current.scrollHeight }) }}
          className={`p-1 ${autoScroll ? 'text-blue-400' : 'text-neutral-500 hover:text-neutral-300'}`}
          title="Auto-scroll"
        >
          <ArrowDown className="size-3.5" />
        </button>
      </div>

      {/* Log entries */}
      <div ref={containerRef} onScroll={onScroll} className="flex-1 overflow-auto font-mono text-[11px] leading-relaxed">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {entries.length === 0 ? 'Waiting for logs...' : 'No matching entries'}
          </div>
        ) : (
          <table className="w-full">
            <tbody>
              {filtered.map(e => {
                const lc = LEVEL_COLORS[e.level] ?? LEVEL_COLORS.debug
                const extra = e.parsed
                  ? Object.entries(e.parsed).filter(([k]) => !HIDDEN_KEYS.has(k) && k !== '')
                  : []
                return (
                  <tr key={e.id} className={`${lc.bg} border-b border-neutral-800/50 hover:bg-neutral-800/50 align-top`}>
                    {/* Level */}
                    <td className={`px-1.5 py-0.5 ${lc.text} font-semibold w-8 shrink-0`}>{lc.label}</td>
                    {/* Time */}
                    <td className="px-1.5 py-0.5 text-neutral-500 w-20 shrink-0 tabular-nums">{formatTime(e.time)}</td>
                    {/* Type */}
                    <td className="px-1.5 py-0.5 text-cyan-400/70 w-28 shrink-0 truncate">{e.type}</td>
                    {/* Message + fields */}
                    <td className="px-1.5 py-0.5 text-neutral-200">
                      {e.message && <span>{e.message} </span>}
                      {extra.map(([k, v]) => (
                        <span key={k} className="inline-block mr-1.5">
                          <span className="text-neutral-500">{k}</span>
                          <span className="text-neutral-600">=</span>
                          <span className="text-neutral-300">{formatValue(v)}</span>
                        </span>
                      ))}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
