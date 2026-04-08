import { useCallback, useMemo, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Save, RotateCw } from 'lucide-react'
import { useConfig } from '@/lib/ConfigContext'
import { AssertForm } from '@/components/AssertForm'

export default function ConfigVisual() {
  const { config, setConfig, kindSchemas, allKinds, problems, scheduleValidation, dirty, statusText, save, reload } = useConfig()

  const services: Record<string, Record<string, any>> = config?.Services ?? {}

  const allServicesMap = useMemo(() => {
    const map: Record<string, { kind: string }> = {}
    for (const [name, svc] of Object.entries(services))
      map[name] = { kind: svc?.kind ?? '' }
    return map
  }, [services])

  const serviceGroups = useMemo(() => {
    const groups: Record<string, string[]> = {}
    for (const name of Object.keys(services)) {
      const kind = services[name]?.kind ?? ''
      const prefix = kind.split('::')[0] || 'other'
      ;(groups[prefix] ??= []).push(name)
    }
    return groups
  }, [services])

  const updateService = useCallback((name: string, value: Record<string, any>) => {
    if (!config) return
    const next = { ...config, Services: { ...config.Services, [name]: value } }
    setConfig(next)
    scheduleValidation(next)
  }, [config, setConfig, scheduleValidation])

  // Sidebar click → scroll visual to service
  useEffect(() => {
    const handler = (e: Event) => {
      const name = (e as CustomEvent).detail as string
      document.getElementById(`svc-${name}`)?.scrollIntoView({ block: 'start' })
    }
    window.addEventListener('ng-scroll-to-service', handler)
    return () => window.removeEventListener('ng-scroll-to-service', handler)
  }, [])

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-4 py-1.5 border-b border-border bg-card">
        <h1 className="text-sm font-semibold mr-3">Configuration</h1>
        <Button size="sm" variant="outline" onClick={save} className="gap-1.5 h-7">
          <Save size={14} /> Save
        </Button>
        <Button size="sm" variant="outline" onClick={reload} className="gap-1.5 h-7">
          <RotateCw size={14} /> Reload
        </Button>
        {dirty && <Badge variant="outline" className="text-[10px] border-amber-600 text-amber-500">unsaved</Badge>}
        {statusText && <span className="ml-auto text-xs text-muted-foreground">{statusText}</span>}
      </div>

      {/* Waterfall */}
      <div className="flex-1 overflow-auto">
        {!config ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">Loading...</div>
        ) : (
          <div className="p-2 space-y-4">
            {Object.entries(serviceGroups).map(([prefix, names]) => (
              <div key={prefix}>
                <div className="text-[10px] font-medium text-neutral-600 uppercase tracking-wider mb-2">{prefix}</div>
                {names.map(name => {
                  const svc = services[name]
                  if (!svc) return null
                  const kind = svc.kind ?? ''
                  const kindSchema = kindSchemas.get(kind)
                  const svcProblems = problems.filter(p => p.service === name)
                  return (
                    <div key={name} id={`svc-${name}`} className="mb-3">
                      <div className="flex items-center gap-2 mb-1.5 sticky top-0 bg-background/90 backdrop-blur-sm py-0.5 z-10">
                        <span className="text-sm font-semibold font-mono">{name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400">{kind}</span>
                        {svcProblems.length > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">
                            {svcProblems.length} error{svcProblems.length > 1 ? 's' : ''}
                          </span>
                        )}
                      </div>

                      <div id={`field-${name}.kind`} className="mb-1.5">
                        <label className="text-xs font-medium text-neutral-300 block mb-0.5">kind</label>
                        <select
                          value={kind}
                          onChange={(e) => updateService(name, { kind: e.target.value })}
                          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground"
                        >
                          {allKinds.map(k => <option key={k} value={k}>{k}</option>)}
                        </select>
                      </div>

                      {kindSchema && (
                        <AssertForm
                          schema={kindSchema.properties}
                          required={kindSchema.required}
                          value={svc}
                          onChange={(v) => updateService(name, v)}
                          kindSchemas={kindSchemas}
                          allServices={allServicesMap}
                          path={name}
                          depth={0}
                        />
                      )}

                      {svcProblems.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {svcProblems.map((p, i) => (
                            <div key={i} className="text-xs text-red-400 bg-red-500/5 rounded px-2 py-1">
                              [{p.phase}] {p.message}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="border-b border-neutral-800 mt-3" />
                    </div>
                  )
                })}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Problems panel */}
      <div className="shrink-0 border-t border-border bg-neutral-950">
        <div className="flex items-center gap-3 px-3 py-1 text-[11px]">
          {problems.length === 0 ? (
            <span className="flex items-center gap-1 text-muted-foreground">
              <span className="text-green-500">✓</span> No problems
            </span>
          ) : (
            <span className="flex items-center gap-1 text-red-400">
              ✗ {problems.length} problem{problems.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
