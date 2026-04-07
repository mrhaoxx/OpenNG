import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import YAML from 'yaml'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Save, RotateCw } from 'lucide-react'
import { fetchSchema, fetchConfigText, csrfFetch } from '@/lib/api'
import { parseKindSchemas, allKindNames } from '@/lib/schema'
import type { KindSchema } from '@/lib/schema'
import { ServiceForm } from '@/components/ServiceForm'

interface ConfigError {
  service: string
  kind: string
  phase: string
  message: string
}

export default function ConfigVisual({ selectedService }: { selectedService: string | null }) {
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
        try {
          setConfig(YAML.parse(yamlText) ?? {})
        } catch {
          setStatusText('Failed to parse YAML')
        }
      })
      .catch(() => setStatusText('Failed to load config'))
  }, [])

  const allKinds = useMemo(() => allKindNames(kindSchemas), [kindSchemas])
  const services: Record<string, Record<string, any>> = config?.Services ?? {}

  const allServicesMap = useMemo(() => {
    const map: Record<string, { kind: string }> = {}
    for (const [name, svc] of Object.entries(services)) {
      map[name] = { kind: svc?.kind ?? '' }
    }
    return map
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
    } catch {
      setStatusText('Save failed')
    }
  }, [config])

  const reload = useCallback(async () => {
    setStatusText('Reloading...')
    try {
      setConfig(YAML.parse(await fetchConfigText()) ?? {})
      setDirty(false)
      setStatusText('Reloaded')
    } catch {
      setStatusText('Reload failed')
    }
  }, [])

  const selectedSvc = selectedService ? services[selectedService] : null
  const selectedKindSchema = selectedSvc ? kindSchemas.get(selectedSvc.kind) ?? null : null

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
        {dirty && (
          <Badge variant="outline" className="text-[10px] border-amber-600 text-amber-500">unsaved</Badge>
        )}
        {statusText && <span className="ml-auto text-xs text-muted-foreground">{statusText}</span>}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {!config && (
          <div className="flex items-center justify-center h-full text-muted-foreground">Loading...</div>
        )}
        {config && !selectedService && (
          <div className="flex items-center justify-center h-full text-muted-foreground">Select a service from the sidebar</div>
        )}
        {config && selectedService && selectedSvc && (
          <ServiceForm
            serviceName={selectedService}
            value={selectedSvc}
            kindSchema={selectedKindSchema}
            kindSchemas={kindSchemas}
            allServices={allServicesMap}
            allKinds={allKinds}
            onChange={(v) => updateService(selectedService, v)}
            problems={problems}
          />
        )}
      </div>
    </div>
  )
}
