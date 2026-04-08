import { useState, useRef, useEffect, useCallback } from 'react'
import { Link2, Layers } from 'lucide-react'
import { useConfig } from '@/lib/ConfigContext'

interface DrefValueProps {
  value: string
  onChange: (v: string) => void
}

function parseDref(value: string): { path: string, spread: boolean, incomplete: boolean } | null {
  if (!value.startsWith('$dref{')) return null
  if (value.endsWith('...')) return { path: value.slice(6, -4), spread: true, incomplete: false }
  if (value.endsWith('}')) return { path: value.slice(6, -1), spread: false, incomplete: false }
  // Incomplete: $dref{ or $dref{partial.path (no closing })
  return { path: value.slice(6), spread: false, incomplete: true }
}

function toDrefString(path: string, spread: boolean): string {
  return `$dref{${path}}${spread ? '...' : ''}`
}

export function DrefValue({ value, onChange }: DrefValueProps) {
  const { drefPaths } = useConfig()
  const parsed = parseDref(value)
  const [editing, setEditing] = useState(parsed?.incomplete ?? false)
  const [draft, setDraft] = useState(parsed?.incomplete ? (parsed?.path ?? '') : '')
  const [draftSpread, setDraftSpread] = useState(parsed?.spread ?? false)
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [selectedIdx, setSelectedIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  if (!parsed) return null

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

  // Show suggestions on mount for incomplete drefs
  useEffect(() => {
    if (parsed?.incomplete && editing) updateSuggestions(draft)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Scroll selected suggestion into view
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

  return (
    <button
      type="button"
      onClick={startEditing}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono min-w-0 cursor-pointer transition-colors ${
        parsed.spread
          ? 'bg-violet-500/10 border border-violet-500/20 text-violet-300 hover:bg-violet-500/20'
          : 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 hover:bg-cyan-500/20'
      }`}
    >
      {parsed.spread ? <Layers className="size-3 shrink-0" /> : <Link2 className="size-3 shrink-0" />}
      <span className="truncate">{parsed.path}</span>
      {parsed.spread && <span className="opacity-60 shrink-0">...</span>}
    </button>
  )
}

/** Check if a string is a $dref reference (complete or incomplete) */
export function isDref(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith('$dref{')
}
