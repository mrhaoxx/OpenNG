import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { JsonSchema, KindSchema } from '@/lib/schema'
import { classifyField, defaultForType } from '@/lib/schema'
import { PtrField } from './PtrField'
import { ListEditor } from './ListEditor'
import { MapEditor } from './MapEditor'

export interface AssertFormProps {
  schema: Record<string, JsonSchema>
  required: string[]
  value: Record<string, any>
  onChange: (v: Record<string, any>) => void
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  path: string
  depth: number
}

const INPUT_CLS = 'bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-full'

function placeholderFor(fieldType: string): string {
  switch (fieldType) {
    case 'duration': return 'e.g. 30s, 5m, 1h'
    case 'url': return 'https://...'
    case 'hostname': return 'example.com'
    case 'regexp': return 'regex pattern'
    default: return ''
  }
}

export function AssertForm({
  schema,
  required,
  value,
  onChange,
  kindSchemas,
  allServices,
  path,
  depth,
}: AssertFormProps) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const requiredSet = new Set(required)

  const update = (key: string, val: any) => {
    onChange({ ...value, [key]: val })
  }

  const toggleCollapse = (key: string) => {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  return (
    <div className="space-y-3">
      {Object.entries(schema).map(([key, fieldSchema]) => {
        if (key === 'kind') return null

        const fieldType = classifyField(fieldSchema)
        const isRequired = requiredSet.has(key)
        const fieldValue = value[key] ?? defaultForType(fieldSchema, fieldType)
        const fieldPath = path ? `${path}.${key}` : key

        return (
          <div key={key} id={`field-${fieldPath}`} className="mb-3">
            {/* Label */}
            <div className="flex items-center gap-1.5 mb-1">
              {/* Collapse toggle for nested objects */}
              {fieldType === 'object' && fieldSchema.properties && (
                <button
                  type="button"
                  onClick={() => toggleCollapse(key)}
                  className="text-neutral-400 hover:text-neutral-200 -ml-1"
                >
                  {collapsed[key]
                    ? <ChevronRight className="size-3.5" />
                    : <ChevronDown className="size-3.5" />
                  }
                </button>
              )}
              <label className="text-sm font-medium text-neutral-300">
                {key}
              </label>
              {isRequired && (
                <span className="text-[10px] font-medium text-amber-500/80 bg-amber-500/10 rounded px-1 py-px">
                  required
                </span>
              )}
            </div>

            {/* Description */}
            {fieldSchema.description && (
              <p className="text-xs text-neutral-500 mb-1.5">{fieldSchema.description}</p>
            )}

            {/* Field input */}
            {renderField(
              fieldType,
              fieldSchema,
              fieldValue,
              (v) => update(key, v),
              kindSchemas,
              allServices,
              fieldPath,
              depth,
              collapsed[key] ?? false,
            )}
          </div>
        )
      })}
    </div>
  )
}

function renderField(
  fieldType: string,
  fieldSchema: JsonSchema,
  value: any,
  onChange: (v: any) => void,
  kindSchemas: Map<string, KindSchema>,
  allServices: Record<string, { kind: string }>,
  path: string,
  depth: number,
  isCollapsed: boolean,
) {
  // If schema is untyped (e.g. `any` in Go) but the actual value is an object, render as map
  if (fieldType === 'string' && typeof value === 'object' && value !== null && !Array.isArray(value)) {
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

  switch (fieldType) {
    case 'string':
    case 'duration':
    case 'url':
    case 'hostname':
    case 'regexp':
      return (
        <input
          type="text"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholderFor(fieldType)}
          className={INPUT_CLS}
        />
      )

    case 'integer':
      return (
        <input
          type="number"
          value={value ?? 0}
          onChange={(e) => onChange(parseInt(e.target.value) || 0)}
          className={INPUT_CLS}
        />
      )

    case 'boolean':
      return (
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={!!value}
            onChange={(e) => onChange(e.target.checked)}
            className="sr-only peer"
          />
          <div className="w-8 h-4.5 bg-neutral-700 rounded-full peer peer-checked:bg-blue-600 peer-focus-visible:ring-2 peer-focus-visible:ring-blue-500/50 after:content-[''] after:absolute after:top-0.5 after:start-[2px] after:bg-neutral-300 after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:after:translate-x-full peer-checked:after:bg-white" />
        </label>
      )

    case 'ptr':
      return (
        <PtrField
          value={value}
          schema={fieldSchema}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={onChange}
          path={path}
          depth={depth}
        />
      )

    case 'array':
      return (
        <ListEditor
          value={Array.isArray(value) ? value : []}
          itemSchema={fieldSchema.items ?? { type: 'string' }}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={onChange}
          path={path}
          depth={depth}
        />
      )

    case 'object': {
      // Object with additionalProperties (map-style)
      if (
        fieldSchema.additionalProperties &&
        typeof fieldSchema.additionalProperties === 'object' &&
        !fieldSchema.properties
      ) {
        return (
          <MapEditor
            value={typeof value === 'object' && value !== null ? value : {}}
            valueSchema={fieldSchema.additionalProperties}
            kindSchemas={kindSchemas}
            allServices={allServices}
            onChange={onChange}
            path={path}
            depth={depth}
          />
        )
      }

      // Object with fixed properties (nested form)
      if (fieldSchema.properties) {
        if (isCollapsed) return null

        return (
          <div className="border-l border-neutral-700 pl-3 mt-1">
            <AssertForm
              schema={fieldSchema.properties}
              required={fieldSchema.required ?? []}
              value={typeof value === 'object' && value !== null ? value : {}}
              onChange={onChange}
              kindSchemas={kindSchemas}
              allServices={allServices}
              path={path}
              depth={depth + 1}
            />
          </div>
        )
      }

      // Fallback: raw JSON text
      return (
        <input
          type="text"
          value={typeof value === 'object' ? JSON.stringify(value) : (value ?? '')}
          onChange={(e) => {
            try { onChange(JSON.parse(e.target.value)) } catch { /* ignore */ }
          }}
          placeholder="JSON object"
          className={INPUT_CLS}
        />
      )
    }

    default:
      return (
        <input
          type="text"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value)}
          className={INPUT_CLS}
        />
      )
  }
}
