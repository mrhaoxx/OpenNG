import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { Link2, Layers, AlertCircle } from 'lucide-react'
import { useConfig } from '@/lib/ConfigContext'

interface DrefValueProps {
  value: string
  onChange: (v: string) => void
}

function parseDref(value: string): { path: string, spread: boolean, incomplete: boolean } | null {
  if (!value.startsWith('$dref{')) return null
  if (value.endsWith('...')) return { path: value.slice(6, -4), spread: true, incomplete: false }
  if (value.endsWith('}')) return { path: value.slice(6, -1), spread: false, incomplete: false }
  return { path: value.slice(6), spread: false, incomplete: true }
}

function toDrefString(path: string, spread: boolean): string {
  return `$dref{${path}}${spread ? '...' : ''}`
}

/** Resolve a dref path against config.Services, returning the value or undefined */
function resolveDrefPath(config: Record<string, any> | null, path: string): { found: boolean, value?: any } {
  if (!config?.Services || !path) return { found: false }
  const segments = path.split('.')
  let current: any = config.Services
  for (const seg of segments) {
    if (current == null || typeof current !== 'object') return { found: false }
    // Try direct key lookup
    if (seg in current) {
      current = current[seg]
      continue
    }
    // Try named list item lookup (list items with 'name' field)
    if (Array.isArray(current)) {
      const item = current.find((it: any) => typeof it === 'object' && it?.name === seg)
      if (item) { current = item; continue }
    }
    return { found: false }
  }
  return { found: true, value: current }
}

function PreviewValue({ value }: { value: any }) {
  if (value == null) return <span className="text-neutral-500">null</span>
  if (typeof value === 'string') return <span className="text-green-300">"{value.length > 80 ? value.slice(0, 77) + '...' : value}"</span>
  if (typeof value === 'number') return <span className="text-amber-300">{value}</span>
  if (typeof value === 'boolean') return <span className="text-blue-300">{String(value)}</span>

  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-neutral-500">[]</span>
    return (
      <div className="space-y-0.5">
        {value.slice(0, 8).map((item, i) => (
          <div key={i} className="flex gap-1">
            <span className="text-neutral-600 shrink-0">{i}:</span>
            <PreviewValue value={item} />
          </div>
        ))}
        {value.length > 8 && <span className="text-neutral-600">...{value.length - 8} more</span>}
      </div>
    )
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value)
    if (entries.length === 0) return <span className="text-neutral-500">{'{}'}</span>
    return (
      <div className="space-y-0.5">
        {entries.slice(0, 6).map(([k, v]) => (
          <div key={k} className="flex gap-1">
            <span className="text-cyan-400/70 shrink-0">{k}:</span>
            {typeof v === 'object' ? (
              <span className="text-neutral-500">{Array.isArray(v) ? `[${(v as any[]).length}]` : `{${Object.keys(v as object).length} keys}`}</span>
            ) : (
              <PreviewValue value={v} />
            )}
          </div>
        ))}
        {entries.length > 6 && <span className="text-neutral-600">...{entries.length - 6} more</span>}
      </div>
    )
  }

  return <span>{String(value)}</span>
}

export function DrefValue({ value, onChange }: DrefValueProps) {
  const { drefPaths, config } = useConfig()
  const parsed = parseDref(value)
  const [editing, setEditing] = useState(parsed?.incomplete ?? false)
  const [draft, setDraft] = useState(parsed?.incomplete ? (parsed?.path ?? '') : '')
  const [draftSpread, setDraftSpread] = useState(parsed?.spread ?? false)
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [showPreview, setShowPreview] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  if (!parsed) return null

  // Check if reference exists
  const resolved = useMemo(() => {
    if (parsed.incomplete) return { found: false }
    return resolveDrefPath(config, parsed.path)
  }, [config, parsed.path, parsed.incomplete])

  const pathExists = resolved.found
  const isExactPath = drefPaths.includes(parsed.path)
  const refValid = pathExists || isExactPath

  const startEditing = useCallback(() => {
    setDraft(parsed.path)
    setDraftSpread(parsed.spread)
    setEditing(true)
  }, [parsed.path, parsed.spread])

  const commit = useCallback(() => {
    onChange(toDrefString(draft.trim() || parsed.path, draftSpread))
    setEditing(false)
  }, [draft, draftSpread, parsed.path, onChange])

  const updateSuggestions = useCallback((text: string) => {
    if (!text) { setSuggestions(drefPaths.slice(0, 15)); setSelectedIdx(0); return }
    const lower = text.toLowerCase()
    const matched = drefPaths.filter(p => p.toLowerCase().includes(lower)).slice(0, 15)
    setSuggestions(matched)
    setSelectedIdx(0)
  }, [drefPaths])

  useEffect(() => {
    if (parsed?.incomplete && editing) updateSuggestions(draft)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!listRef.current) return
    const el = listRef.current.children[selectedIdx] as HTMLElement
    el?.scrollIntoView({ block: 'nearest' })
  }, [selectedIdx])

  if (editing) {
    return (
      <div className="relative">
        <div className="flex items-center gap-1">
          {draftSpread
            ? <Layers className="size-3 text-violet-400 shrink-0" />
            : <Link2 className="size-3 text-cyan-400 shrink-0" />
          }
          <input
            ref={inputRef}
            type="text"
            value={draft}
            onChange={(e) => { setDraft(e.target.value); updateSuggestions(e.target.value) }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                if (suggestions.length > 0) {
                  const picked = suggestions[selectedIdx]
                  setDraft(picked)
                  setSuggestions([])
                } else {
                  commit()
                }
                e.preventDefault()
              }
              if (e.key === 'Escape') { setSuggestions([]); setEditing(false) }
              if (e.key === 'ArrowDown') { setSelectedIdx(i => Math.min(i + 1, suggestions.length - 1)); e.preventDefault() }
              if (e.key === 'ArrowUp') { setSelectedIdx(i => Math.max(i - 1, 0)); e.preventDefault() }
              if (e.key === 'Tab' && suggestions.length > 0) {
                setDraft(suggestions[selectedIdx])
                setSuggestions([])
                e.preventDefault()
              }
            }}
            onBlur={() => { setTimeout(() => { setSuggestions([]); commit() }, 150) }}
            autoFocus
            className={`border rounded px-1.5 py-0.5 text-xs text-foreground font-mono flex-1 min-w-0 bg-neutral-800 ${
              draftSpread ? 'border-violet-500/30' : 'border-cyan-500/30'
            }`}
            placeholder="service.field.path"
          />
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => setDraftSpread(!draftSpread)}
            className={`px-1 py-0.5 text-[10px] rounded border ${draftSpread ? 'border-violet-500/50 text-violet-400 bg-violet-500/10' : 'border-neutral-700 text-neutral-500'}`}
            title="Spread (...)"
          >
            ...
          </button>
        </div>
        {suggestions.length > 0 && (
          <div ref={listRef} className="absolute z-20 mt-0.5 left-0 right-0 bg-neutral-900 border border-neutral-700 rounded shadow-lg max-h-40 overflow-auto">
            {suggestions.map((s, i) => (
              <button
                key={s}
                type="button"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => { setDraft(s); setSuggestions([]) }}
                className={`w-full text-left px-2 py-0.5 text-xs font-mono truncate ${
                  i === selectedIdx ? 'bg-cyan-500/20 text-cyan-200' : 'text-neutral-400 hover:bg-neutral-800'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>
    )
  }

  // Display mode
  const baseColors = parsed.spread
    ? refValid
      ? 'bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20'
      : 'bg-red-500/10 border-red-500/30 text-red-300 hover:bg-red-500/15'
    : refValid
      ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-300 hover:bg-cyan-500/20'
      : 'bg-red-500/10 border-red-500/30 text-red-300 hover:bg-red-500/15'

  return (
    <div className="relative inline-flex items-center gap-1 group"
      onMouseEnter={() => setShowPreview(true)}
      onMouseLeave={() => setShowPreview(false)}
    >
      <button
        type="button"
        onClick={startEditing}
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono min-w-0 cursor-pointer transition-colors border ${baseColors}`}
      >
        {!refValid && <AlertCircle className="size-3 shrink-0 text-red-400" />}
        {refValid && (parsed.spread ? <Layers className="size-3 shrink-0" /> : <Link2 className="size-3 shrink-0" />)}
        <span className="truncate">{parsed.path}</span>
        {parsed.spread && <span className="opacity-60 shrink-0">...</span>}
      </button>

      {/* Hover preview / error tooltip */}
      {showPreview && !editing && (
        <div className="absolute z-30 bottom-full mb-1 left-0 max-w-xs">
          {refValid ? (
            <div className="bg-neutral-900 border border-neutral-700 rounded px-2 py-1.5 shadow-lg text-[10px] font-mono max-h-48 overflow-auto">
              <PreviewValue value={resolved.value} />
            </div>
          ) : (
            <div className="bg-red-950 border border-red-500/30 rounded px-2 py-1 shadow-lg text-[10px] text-red-300">
              reference not found: <span className="font-mono">{parsed.path}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function isDref(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith('$dref{')
}
