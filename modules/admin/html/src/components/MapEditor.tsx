import { useState, useCallback } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import type { JsonSchema, KindSchema } from '@/lib/schema'
import { classifyField } from '@/lib/schema'
import { AssertForm } from './AssertForm'
import { ListEditor } from './ListEditor'
import { PtrField } from './PtrField'
import { AnyValueEditor } from './AnyValueEditor'

export interface MapEditorProps {
  value: Record<string, any>
  valueSchema: JsonSchema
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  onChange: (v: Record<string, any>) => void
  path: string
  depth: number
}

/** Editable map key that only commits on blur/enter — prevents focus loss while typing */
function MapKeyInput({ value, onCommit, className, placeholder }: {
  value: string
  onCommit: (newKey: string) => void
  className?: string
  placeholder?: string
}) {
  const [draft, setDraft] = useState(value)
  // Sync external changes (e.g. after reorder) but not while user is typing
  if (value !== draft && document.activeElement?.getAttribute('data-map-key') !== value) {
    setDraft(value)
  }
  const commit = useCallback(() => {
    const trimmed = draft.trim()
    if (trimmed && trimmed !== value) onCommit(trimmed)
    else setDraft(value) // revert if empty or unchanged
  }, [draft, value, onCommit])

  return (
    <input
      type="text"
      data-map-key={value}
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => { if (e.key === 'Enter') commit() }}
      className={className}
      placeholder={placeholder}
    />
  )
}

export function MapEditor({
  value,
  valueSchema,
  kindSchemas,
  allServices,
  onChange,
  path,
  depth,
}: MapEditorProps) {
  const entries = Object.entries(value)
  const fieldType = classifyField(valueSchema)

  const updateKey = (oldKey: string, newKey: string) => {
    if (newKey === oldKey) return
    const result: Record<string, any> = {}
    for (const [k, v] of Object.entries(value)) {
      result[k === oldKey ? newKey : k] = v
    }
    onChange(result)
  }

  const updateValue = (key: string, val: any) => {
    onChange({ ...value, [key]: val })
  }

  const removeEntry = (key: string) => {
    const { [key]: _, ...rest } = value
    onChange(rest)
  }

  const addEntry = () => {
    let newKey = 'new_key'
    let i = 1
    while (newKey in value) {
      newKey = `new_key_${i++}`
    }
    let defaultVal: any = ''
    if (fieldType === 'integer') defaultVal = 0
    else if (fieldType === 'boolean') defaultVal = false
    else if (fieldType === 'object') defaultVal = {}
    else if (fieldType === 'array') defaultVal = []
    onChange({ ...value, [newKey]: defaultVal })
  }

  const renderValue = (key: string, val: any) => {
    // Untyped schema (Go `any`): always use AnyValueEditor with type switcher
    if (fieldType === 'string' && !valueSchema.type && !valueSchema.anyOf && !valueSchema.pattern && !valueSchema.errorMessage) {
      return (
        <AnyValueEditor
          value={val}
          onChange={(v) => updateValue(key, v)}
          kindSchemas={kindSchemas}
          allServices={allServices}
          path={`${path}.${key}`}
          depth={depth + 1}
        />
      )
    }

    // Array values
    if (fieldType === 'array' || valueSchema.type === 'array') {
      return (
        <ListEditor
          value={Array.isArray(val) ? val : []}
          itemSchema={valueSchema.items ?? {}}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={(v) => updateValue(key, v)}
          path={`${path}.${key}`}
          depth={depth + 1}
        />
      )
    }

    // Ptr values
    if (fieldType === 'ptr') {
      return (
        <PtrField
          value={val}
          schema={valueSchema}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={(v) => updateValue(key, v)}
          path={`${path}.${key}`}
          depth={depth + 1}
        />
      )
    }

    // Object with named properties
    if (valueSchema.type === 'object' && valueSchema.properties) {
      return (
        <AssertForm
          schema={valueSchema.properties}
          required={valueSchema.required ?? []}
          value={typeof val === 'object' && val !== null ? val : {}}
          onChange={(v) => updateValue(key, v)}
          kindSchemas={kindSchemas}
          allServices={allServices}
          path={`${path}.${key}`}
          depth={depth + 1}
        />
      )
    }

    if (fieldType === 'boolean') {
      return (
        <input
          type="checkbox"
          checked={!!val}
          onChange={(e) => updateValue(key, e.target.checked)}
          className="h-4 w-4 rounded border-neutral-700 bg-neutral-800 accent-blue-500"
        />
      )
    }

    if (fieldType === 'integer') {
      return (
        <input
          type="number"
          value={val ?? 0}
          onChange={(e) => updateValue(key, parseInt(e.target.value) || 0)}
          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-full"
        />
      )
    }

    // Default: string-like
    return (
      <input
        type="text"
        value={typeof val === 'object' ? JSON.stringify(val) : (val ?? '')}
        onChange={(e) => updateValue(key, e.target.value)}
        className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-full"
      />
    )
  }

  return (
    <div className="space-y-1">
      {entries.map(([key, val], idx) => {
        const isComplex = fieldType === 'array' || fieldType === 'object' || fieldType === 'ptr' ||
          (valueSchema.type === 'array') || (valueSchema.type === 'object' && valueSchema.properties)

        if (isComplex) {
          return (
            <div key={idx} id={`field-${path}.${key}`} className="border border-neutral-800 rounded-md p-2 bg-neutral-900/50">
              <div className="flex items-center gap-2 mb-2">
                <MapKeyInput
                  value={key}
                  onCommit={(newKey) => updateKey(key, newKey)}
                  className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground font-mono"
                  placeholder="key"
                />
                <button
                  type="button"
                  onClick={() => removeEntry(key)}
                  className="p-1 text-neutral-500 hover:text-red-400 ml-auto"
                  title="Remove entry"
                >
                  <Trash2 className="size-4" />
                </button>
              </div>
              {renderValue(key, val)}
            </div>
          )
        }

        return (
          <div key={idx} id={`field-${path}.${key}`} className="flex items-start gap-2">
            <MapKeyInput
              value={key}
              onCommit={(newKey) => updateKey(key, newKey)}
              className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-40 shrink-0"
              placeholder="key"
            />
            <div className="flex-1 min-w-0">
              {renderValue(key, val)}
            </div>
            <button
              type="button"
              onClick={() => removeEntry(key)}
              className="p-1 text-neutral-500 hover:text-red-400 shrink-0 mt-0.5"
              title="Remove entry"
            >
              <Trash2 className="size-4" />
            </button>
          </div>
        )
      })}
      <button
        type="button"
        onClick={addEntry}
        className="flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-200 transition-colors"
      >
        <Plus className="size-3.5" />
        Add entry
      </button>
    </div>
  )
}
