import { useState, useRef, useCallback, useEffect } from 'react'
import { ChevronDown, ChevronRight, Braces, Hash, AlertCircle, Check } from 'lucide-react'
import type { ExprEnvNode } from '@/lib/schema'
import { getExprCompletions, type ExprCompletion } from '@/lib/expr'
import { checkExpr } from '@/lib/api'
import { useConfig } from '@/lib/ConfigContext'

interface ExprFieldProps {
  value: string
  onChange: (v: string) => void
  env?: ExprEnvNode[]
  kind?: string
  field?: string
  path?: string  // unique path for error reporting
}

const INPUT_CLS = 'bg-neutral-800 border border-neutral-700 rounded px-1.5 py-0.5 text-xs text-foreground w-full font-mono resize-y min-h-[28px]'

export function ExprField({ value, onChange, env, kind, field, path }: ExprFieldProps) {
  const { setExprError } = useConfig()
  const [showRef, setShowRef] = useState(false)
  const [completions, setCompletions] = useState<ExprCompletion[]>([])
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [lintError, setLintError] = useState<string | null>(null)
  const [lintOk, setLintOk] = useState(false)
  const lintTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const replaceLenRef = useRef(0)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Debounced lint check
  const errorKey = path ?? `${kind}:${field}`
  useEffect(() => {
    if (!kind || !field || !value?.trim()) {
      setLintError(null)
      setLintOk(false)
      setExprError(errorKey, null)
      return
    }
    if (lintTimerRef.current) clearTimeout(lintTimerRef.current)
    lintTimerRef.current = setTimeout(() => {
      checkExpr(value, kind, field).then(res => {
        const err = res.ok ? null : (res.error ?? 'unknown error')
        setLintError(err)
        setLintOk(res.ok)
        setExprError(errorKey, err)
      }).catch(() => {
        setLintError(null)
        setLintOk(false)
        setExprError(errorKey, null)
      })
    }, 500)
    return () => {
      if (lintTimerRef.current) clearTimeout(lintTimerRef.current)
      setExprError(errorKey, null) // clean up on unmount
    }
  }, [value, kind, field, errorKey, setExprError])

  const updateCompletions = useCallback(() => {
    if (!env?.length || !textareaRef.current) {
      setCompletions([])
      return
    }
    const el = textareaRef.current
    const before = el.value.substring(0, el.selectionStart)
    const { items, replaceLen } = getExprCompletions(before, env)
    setCompletions(items)
    replaceLenRef.current = replaceLen
    setSelectedIdx(0)
  }, [env])

  const applyCompletion = useCallback((item: ExprCompletion) => {
    const el = textareaRef.current
    if (!el) return
    const pos = el.selectionStart
    const text = el.value

    const replaceStart = pos - replaceLenRef.current
    const newText = text.substring(0, replaceStart) + item.insertText + text.substring(pos)

    onChange(newText)
    setCompletions([])

    const newPos = replaceStart + item.insertText.length
    requestAnimationFrame(() => {
      el.focus()
      el.setSelectionRange(newPos, newPos)
    })
  }, [onChange])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (completions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIdx(i => Math.min(i + 1, completions.length - 1))
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIdx(i => Math.max(i - 1, 0))
        return
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault()
        applyCompletion(completions[selectedIdx])
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setCompletions([])
        return
      }
    }
    if (e.key === 'Enter' && !e.shiftKey) {
      e.stopPropagation()
    }
  }, [completions, selectedIdx, applyCompletion])

  useEffect(() => {
    if (!listRef.current) return
    const el = listRef.current.children[selectedIdx] as HTMLElement | undefined
    el?.scrollIntoView({ block: 'nearest' })
  }, [selectedIdx])

  return (
    <div className="relative space-y-1">
      <textarea
        ref={textareaRef}
        value={value ?? ''}
        onChange={(e) => {
          onChange(e.target.value)
          requestAnimationFrame(updateCompletions)
        }}
        onKeyDown={handleKeyDown}
        onBlur={() => {
          setTimeout(() => setCompletions([]), 150)
        }}
        placeholder="expression"
        rows={1}
        className={INPUT_CLS}
      />

      {/* Autocomplete dropdown — same style as DrefValue */}
      {completions.length > 0 && (
        <div ref={listRef} className="absolute z-20 mt-0.5 left-0 right-0 bg-neutral-900 border border-neutral-700 rounded shadow-lg max-h-40 overflow-auto">
          {completions.map((item, i) => (
            <button
              key={item.label}
              type="button"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => applyCompletion(item)}
              onMouseEnter={() => setSelectedIdx(i)}
              className={`w-full text-left px-2 py-0.5 text-xs font-mono flex items-center gap-2 ${
                i === selectedIdx ? 'bg-cyan-500/20 text-cyan-200' : 'text-neutral-400 hover:bg-neutral-800'
              }`}
            >
              {item.kind === 'function' && <span className="text-purple-400/60 text-[10px] shrink-0">fn</span>}
              {item.kind === 'keyword' && <span className="text-amber-400/60 text-[10px] shrink-0">kw</span>}
              <span className="truncate">{item.label}</span>
              <span className="ml-auto text-neutral-600 truncate text-[10px]">{item.type}</span>
            </button>
          ))}
        </div>
      )}

      {/* Lint status */}
      {lintError && (
        <div className="flex items-start gap-1 text-[10px] text-red-400">
          <AlertCircle className="size-3 shrink-0 mt-0.5" />
          <span className="font-mono">{lintError}</span>
        </div>
      )}
      {lintOk && !lintError && value?.trim() && (
        <div className="flex items-center gap-1 text-[10px] text-green-500">
          <Check className="size-3" />
          <span>valid</span>
        </div>
      )}

      {/* Reference panel */}
      {env && env.length > 0 && (
        <button
          type="button"
          onClick={() => setShowRef(!showRef)}
          className="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 transition-colors"
        >
          <Braces className="size-3" />
          {showRef ? 'Hide' : 'Show'} environment reference
        </button>
      )}
      {showRef && env && (
        <div className="border border-neutral-700 rounded bg-neutral-900/80 p-2 text-[11px] font-mono max-h-64 overflow-y-auto">
          {env.map((node) => (
            <EnvNodeView key={node.name} node={node} depth={0} prefix="" />
          ))}
        </div>
      )}
    </div>
  )
}

function EnvNodeView({ node, depth, prefix }: { node: ExprEnvNode; depth: number; prefix: string }) {
  const [expanded, setExpanded] = useState(depth < 1)
  const hasChildren = node.children && node.children.length > 0
  const fullPath = prefix ? `${prefix}.${node.name}` : node.name

  return (
    <div>
      <div
        className="flex items-center gap-1 py-px hover:bg-neutral-800/50 rounded px-1 cursor-default group"
        style={{ paddingLeft: depth * 12 }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="text-neutral-500 hover:text-neutral-300 shrink-0"
          >
            {expanded
              ? <ChevronDown className="size-3" />
              : <ChevronRight className="size-3" />
            }
          </button>
        ) : (
          <span className="w-3 shrink-0" />
        )}
        {node.kind === 'method' ? (
          <Hash className="size-3 text-amber-500/70 shrink-0" />
        ) : (
          <span className="w-3 text-center text-blue-400/70 shrink-0">·</span>
        )}
        <span
          className="text-neutral-200 select-all cursor-text"
          title={`${fullPath} — click to select`}
        >
          {node.name}
        </span>
        <span className="text-neutral-500 ml-1 truncate">
          {node.type}
        </span>
      </div>
      {expanded && hasChildren && node.children!.map((child) => (
        <EnvNodeView key={child.name} node={child} depth={depth + 1} prefix={fullPath} />
      ))}
    </div>
  )
}
