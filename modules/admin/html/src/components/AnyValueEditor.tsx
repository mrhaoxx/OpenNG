import { ListEditor } from './ListEditor'
import { MapEditor } from './MapEditor'
import type { KindSchema } from '@/lib/schema'

export interface AnyValueEditorProps {
  value: any
  onChange: (v: any) => void
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  path: string
  depth: number
}

type ValueType = 'string' | 'number' | 'boolean' | 'list' | 'map'

function detectType(value: any): ValueType {
  if (Array.isArray(value)) return 'list'
  if (typeof value === 'object' && value !== null) return 'map'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'number') return 'number'
  return 'string'
}

function defaultFor(type: ValueType): any {
  switch (type) {
    case 'string': return ''
    case 'number': return 0
    case 'boolean': return false
    case 'list': return []
    case 'map': return {}
  }
}

function TypeSwitcher({ current, onChange }: { current: ValueType, onChange: (t: ValueType) => void }) {
  return (
    <select
      value={current}
      onChange={(e) => onChange(e.target.value as ValueType)}
      className="bg-neutral-800 border border-neutral-700 rounded px-1 py-0.5 text-[10px] text-neutral-400 shrink-0"
    >
      <option value="string">str</option>
      <option value="number">num</option>
      <option value="boolean">bool</option>
      <option value="list">list</option>
      <option value="map">map</option>
    </select>
  )
}

/**
 * Renders any value by inferring the type at runtime.
 * Used for schema-less fields (Go `any` / empty JSON Schema `{}`).
 */
export function AnyValueEditor({ value, onChange, kindSchemas, allServices, path, depth }: AnyValueEditorProps) {
  const currentType = detectType(value)

  const switchType = (newType: ValueType) => {
    if (newType !== currentType) onChange(defaultFor(newType))
  }

  if (currentType === 'list') {
    return (
      <ListEditor
        value={value}
        itemSchema={{}}
        kindSchemas={kindSchemas}
        allServices={allServices}
        onChange={onChange}
        path={path}
        depth={depth}
      />
    )
  }

  if (currentType === 'map') {
    return (
      <MapEditor
        value={value}
        valueSchema={{}}
        kindSchemas={kindSchemas}
        allServices={allServices}
        onChange={onChange}
        path={path}
        depth={depth}
      />
    )
  }

  if (currentType === 'boolean') {
    return (
      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
          className="h-4 w-4 rounded border-neutral-700 bg-neutral-800 accent-blue-500"
        />
        <TypeSwitcher current={currentType} onChange={switchType} />
      </div>
    )
  }

  if (currentType === 'number') {
    return (
      <div className="flex items-center gap-2">
        <input
          type="number"
          value={value}
          onChange={(e) => onChange(parseFloat(e.target.value) || 0)}
          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground flex-1"
        />
        <TypeSwitcher current={currentType} onChange={switchType} />
      </div>
    )
  }

  // Default: string
  return (
    <div className="flex items-center gap-2">
      <input
        type="text"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground flex-1"
      />
      <TypeSwitcher current={currentType} onChange={switchType} />
    </div>
  )
}
