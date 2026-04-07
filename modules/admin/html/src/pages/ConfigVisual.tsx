import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import YAML from 'yaml'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Save, RotateCw } from 'lucide-react'
import { fetchSchema, fetchConfigText, csrfFetch } from '@/lib/api'
import { parseKindSchemas, allKindNames } from '@/lib/schema'
import type { KindSchema } from '@/lib/schema'
import { AssertForm } from '@/components/AssertForm'

interface ConfigError { service: string; kind: string; phase: string; message: string }

export default function ConfigVisual() {
  const [config, setConfig] = useState<Record<string, any> | null>(null)
  const [kindSchemas, setKindSchemas] = useState<Map<string, KindSchema>>(new Map())
  const [problems, setProblems] = useState<ConfigError[]>([])
  const [dirty, setDirty] = useState(false)
  const [statusText, setStatusText] = useState('')
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    Promise.all([fetchSchema(), fetchConfigText()])
      .then(([schemaData, yamlText]) => {
        setKindSchemas(parseKindSchemas(schemaData))
        try { setConfig(YAML.parse(yamlText) ?? {}) } catch { setStatusText('Failed to parse YAML') }
      })
      .catch(() => setStatusText('Failed to load config'))
  }, [])

  const allKinds = useMemo(() => allKindNames(kindSchemas), [kindSchemas])
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

  const scheduleValidation = useCallback((cfg: Record<string, any>) => {
    if (validateTimer.current) clearTimeout(validateTimer.current)
    validateTimer.current = setTimeout(async () => {
      try {
        const resp = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: YAML.stringify(cfg) })
        setProblems(await resp.json())
      } catch { /* ignore */ }
    }, 800)
  }, [])

  const updateService = useCallback((name: string, value: Record<string, any>) => {
    if (!config) return
    const next = { ...config, Services: { ...config.Services, [name]: value } }
    setConfig(next)
    setDirty(true)
    scheduleValidation(next)
  }, [config, scheduleValidation])

  const save = useCallback(async () => {
    if (!config) return
    setStatusText('Saving...')
    try {
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: YAML.stringify(config) })
      setStatusText(resp.ok ? 'Saved' : `Save failed: ${await resp.text()}`)
      if (resp.ok) setDirty(false)
    } catch { setStatusText('Save failed') }
  }, [config])

  const reload = useCallback(async () => {
    setStatusText('Reloading...')
    try {
      setConfig(YAML.parse(await fetchConfigText()) ?? {})
      setDirty(false)
      setStatusText('Reloaded')
    } catch { setStatusText('Reload failed') }
  }, [])

  // Sidebar click → scroll visual to service
  useEffect(() => {
    const handler = (e: Event) => {
      const name = (e as CustomEvent).detail as string
      document.getElementById(`svc-${name}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
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
          <div className="p-4 space-y-6">
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
                    <div key={name} id={`svc-${name}`} className="mb-6">
                      <div className="flex items-center gap-2 mb-3 sticky top-0 bg-background/90 backdrop-blur-sm py-1 z-10">
                        <span className="text-base font-semibold font-mono">{name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400">{kind}</span>
                        {svcProblems.length > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">
                            {svcProblems.length} error{svcProblems.length > 1 ? 's' : ''}
                          </span>
                        )}
                      </div>

                      <div id={`field-${name}.kind`} className="mb-3">
                        <label className="text-sm font-medium text-neutral-300 block mb-1">kind</label>
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

                      <div className="border-b border-neutral-800 mt-4" />
                    </div>
                  )
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
