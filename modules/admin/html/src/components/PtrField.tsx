import { ChevronDown, ChevronRight } from 'lucide-react'
import type { JsonSchema, KindSchema } from '@/lib/schema'
import { parsePtrSchema, compatibleServices, getInlineKindSchema } from '@/lib/schema'
import { AssertForm } from './AssertForm'

export interface PtrFieldProps {
  value: any
  schema: JsonSchema
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  onChange: (v: any) => void
  path: string
  depth: number
}

type Mode = 'reference' | 'inline'

function detectMode(value: any): Mode {
  if (typeof value === 'object' && value !== null && 'kind' in value) {
    return 'inline'
  }
  return 'reference'
}

export function PtrField({
  value,
  schema,
  kindSchemas,
  allServices,
  onChange,
  path,
  depth,
}: PtrFieldProps) {
  const { allowedKinds, isNullable, inlineAllOf } = parsePtrSchema(schema)
  const mode = detectMode(value)
  const compatible = compatibleServices(allServices, allowedKinds)

  const expandInline = () => {
    const kind = allowedKinds[0] ?? ''
    onChange({ kind })
  }

  const collapseToRef = () => {
    onChange('')
  }

  const setNull = () => {
    onChange(null)
  }

  if (mode === 'reference') {
    return (
      <div className="flex items-center gap-2">
        <select
          value={value === null ? '__null__' : (value ?? '')}
          onChange={(e) => {
            const v = e.target.value
            if (v === '__null__') onChange(null)
            else onChange(v)
          }}
          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground flex-1"
        >
          <option value="">— select service —</option>
          {isNullable && <option value="__null__">null</option>}
          {compatible.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        {allowedKinds.length > 0 && (
          <button
            type="button"
            onClick={expandInline}
            className="flex items-center gap-0.5 text-xs text-blue-400 hover:text-blue-300 shrink-0"
            title="Expand inline"
          >
            <ChevronRight className="size-3.5" />
            Inline
          </button>
        )}
      </div>
    )
  }

  // Inline mode
  const currentKind = value?.kind ?? allowedKinds[0] ?? ''
  const kindSchema = getInlineKindSchema(inlineAllOf, currentKind)

  const changeKind = (newKind: string) => {
    onChange({ kind: newKind })
  }

  const changeFields = (fields: Record<string, any>) => {
    onChange({ ...fields, kind: currentKind })
  }

  return (
    <div className="border-l-2 border-blue-500/30 pl-3 space-y-2">
      <div className="flex items-center gap-2">
        <select
          value={currentKind}
          onChange={(e) => changeKind(e.target.value)}
          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground"
        >
          {allowedKinds.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={collapseToRef}
          className="flex items-center gap-0.5 text-xs text-blue-400 hover:text-blue-300 shrink-0"
          title="Collapse to ref"
        >
          <ChevronDown className="size-3.5" />
          Ref
        </button>
        {isNullable && (
          <button
            type="button"
            onClick={setNull}
            className="text-xs text-neutral-400 hover:text-neutral-200"
          >
            Set null
          </button>
        )}
      </div>

      {kindSchema && (
        <AssertForm
          schema={kindSchema.properties}
          required={kindSchema.required}
          value={typeof value === 'object' && value !== null ? value : {}}
          onChange={changeFields}
          kindSchemas={kindSchemas}
          allServices={allServices}
          path={`${path}(${currentKind})`}
          depth={depth + 1}
        />
      )}
    </div>
  )
}
