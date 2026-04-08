import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { AlertCircle } from 'lucide-react'
import type { KindSchema } from '@/lib/schema'
import { AssertForm } from './AssertForm'

interface ServiceFormProps {
  serviceName: string
  value: Record<string, any>
  kindSchema: KindSchema | null
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  allKinds: string[]
  onChange: (v: Record<string, any>) => void
  problems: Array<{ service: string; phase: string; message: string }>
}

export function ServiceForm({
  serviceName,
  value,
  kindSchema,
  kindSchemas,
  allServices,
  allKinds,
  onChange,
  problems,
}: ServiceFormProps) {
  const currentKind = value.kind ?? ''

  const changeKind = (newKind: string) => {
    // Reset fields when kind changes, keep only kind
    onChange({ kind: newKind })
  }

  const changeFields = (fields: Record<string, any>) => {
    onChange({ ...fields, kind: currentKind })
  }

  const serviceProblems = problems.filter((p) => p.service === serviceName)

  return (
    <ScrollArea className="h-full">
      <div className="p-6 max-w-2xl">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <h2 className="text-lg font-mono font-semibold text-foreground">{serviceName}</h2>
          <Badge variant="secondary" className="text-xs">{currentKind}</Badge>
        </div>

        {/* Kind selector */}
        <div className="mb-6">
          <label className="text-sm font-medium text-neutral-300 block mb-1">Kind</label>
          <select
            value={currentKind}
            onChange={(e) => changeKind(e.target.value)}
            className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm text-foreground w-full max-w-xs"
          >
            <option value="">--</option>
            {allKinds.map((k) => (
              <option key={k} value={k}>{k}</option>
            ))}
          </select>
        </div>

        {/* Fields */}
        {kindSchema && (
          <AssertForm
            schema={kindSchema.properties}
            required={kindSchema.required}
            value={value}
            onChange={changeFields}
            kindSchemas={kindSchemas}
            allServices={allServices}
            path={serviceName}
            depth={0}
            order={kindSchema.order}
            exprKind={currentKind}
          />
        )}

        {!kindSchema && currentKind && (
          <p className="text-sm text-neutral-500 italic">No schema found for kind "{currentKind}".</p>
        )}

        {/* Problems */}
        {serviceProblems.length > 0 && (
          <div className="mt-6 space-y-1.5">
            <div className="text-xs font-medium text-red-400 uppercase tracking-wider">Problems</div>
            {serviceProblems.map((p, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-red-300">
                <AlertCircle className="size-4 shrink-0 mt-0.5 text-red-400" />
                <span>
                  <span className="text-neutral-500">[{p.phase}]</span> {p.message}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </ScrollArea>
  )
}
