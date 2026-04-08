import { createContext, useContext, useState, useEffect, useCallback, useRef, useMemo, type ReactNode } from 'react'
import YAML, { parseDocument, isMap, isSeq, isPair, isScalar } from 'yaml'
import { fetchSchema, fetchConfigText, csrfFetch } from './api'
import { parseKindSchemas, allKindNames } from './schema'
import type { KindSchema } from './schema'

export interface ConfigError {
  phase: string
  service: string
  message: string
  fieldPath?: string // full path for precise jump (e.g. "e2.routes[0].service.condition")
}

interface ConfigContextValue {
  /** Raw YAML text — source of truth */
  yamlText: string
  setYamlText: (text: string) => void
  /** Set yamlText without re-parsing config (for when caller already has config) */
  setYamlTextRaw: (text: string) => void
  /** Parsed config object (derived from yamlText) */
  config: Record<string, any> | null
  /** Set config AND sync to yamlText (triggers re-stringify) */
  setConfig: (cfg: Record<string, any>) => void
  /** Set config only — caller manages yamlText separately */
  setConfigOnly: (cfg: Record<string, any>) => void
  /** Schema data */
  kindSchemas: Map<string, KindSchema>
  allKinds: string[]
  /** Validation */
  problems: ConfigError[]
  scheduleValidation: (cfg: Record<string, any>) => void
  /** Dirty flag */
  dirty: boolean
  setDirty: (d: boolean) => void
  /** Status text */
  statusText: string
  setStatusText: (s: string) => void
  /** Save & Reload */
  save: () => Promise<boolean>
  reload: () => Promise<void>
  /** Loading state */
  loading: boolean
  /** All config paths for dref autocomplete (computed from YAML AST) */
  drefPaths: string[]
  /** Raw schema definitions for expr env lookups */
  rawDefinitions: Record<string, any> | undefined
  /** Expr lint errors — keyed by path, set/clear by ExprField instances */
  setExprError: (path: string, error: string | null) => void
}

const ConfigContext = createContext<ConfigContextValue | null>(null)

export function useConfig() {
  const ctx = useContext(ConfigContext)
  if (!ctx) throw new Error('useConfig must be used within ConfigProvider')
  return ctx
}

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [yamlText, setYamlTextState] = useState('')
  const [config, setConfigState] = useState<Record<string, any> | null>(null)
  const [kindSchemas, setKindSchemas] = useState<Map<string, KindSchema>>(new Map())
  const [validationProblems, setValidationProblems] = useState<ConfigError[]>([])
  const [exprErrors, setExprErrors] = useState<Map<string, string>>(new Map())
  const [dirty, setDirty] = useState(false)
  const [statusText, setStatusText] = useState('')
  const [loading, setLoading] = useState(true)
  const [rawDefinitions, setRawDefinitions] = useState<Record<string, any> | undefined>(undefined)
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const setExprError = useCallback((path: string, error: string | null) => {
    setExprErrors(prev => {
      const next = new Map(prev)
      if (error) next.set(path, error)
      else next.delete(path)
      return next
    })
  }, [])

  // Merge validation problems + expr lint errors
  const problems: ConfigError[] = useMemo(() => {
    const exprProblems: ConfigError[] = []
    for (const [path, msg] of exprErrors) {
      const service = path.split('.')[0]
      exprProblems.push({ phase: 'expr', service, message: msg, fieldPath: path })
    }
    return [...validationProblems, ...exprProblems]
  }, [validationProblems, exprErrors])

  const allKinds = allKindNames(kindSchemas)

  // Dref paths from YAML AST — cached, only recompute when text actually changes and editing pauses
  const [drefPaths, setDrefPaths] = useState<string[]>([])
  const drefTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const drefCacheRef = useRef('')
  useEffect(() => {
    if (yamlText === drefCacheRef.current) return
    if (drefTimer.current) clearTimeout(drefTimer.current)
    drefTimer.current = setTimeout(() => {
      if (yamlText === drefCacheRef.current) return
      drefCacheRef.current = yamlText
      setDrefPaths(collectAstPaths(yamlText))
    }, 2000)
  }, [yamlText])

  // Load schema + config on mount
  useEffect(() => {
    Promise.all([fetchSchema(), fetchConfigText()])
      .then(([schemaData, text]) => {
        setKindSchemas(parseKindSchemas(schemaData))
        setRawDefinitions(schemaData.definitions)
        setYamlTextState(text)
        try {
          setConfigState(YAML.parse(text) ?? {})
        } catch {
          setStatusText('Failed to parse YAML')
        }
        setLoading(false)
      })
      .catch(() => {
        setStatusText('Failed to load')
        setLoading(false)
      })
  }, [])

  // Set YAML text without re-parsing (caller already has config)
  const setYamlTextRaw = useCallback((text: string) => {
    setYamlTextState(text)
    setDirty(true)
  }, [])

  // Set YAML text, sync to parsed config, and schedule validation
  const scheduleValidationRef = useRef<(cfg: Record<string, any>) => void>(() => {})
  const setYamlText = useCallback((text: string) => {
    setYamlTextState(text)
    try {
      const parsed = YAML.parse(text)
      if (parsed) {
        setConfigState(parsed)
        scheduleValidationRef.current(parsed)
      }
    } catch { /* invalid YAML, keep old config */ }
    setDirty(true)
  }, [])

  // Set config only (no yamlText sync)
  const setConfigOnly = useCallback((cfg: Record<string, any>) => {
    setConfigState(cfg)
    setDirty(true)
  }, [])

  // Set parsed config and sync to YAML text
  const setConfig = useCallback((cfg: Record<string, any>) => {
    setConfigState(cfg)
    setYamlTextState(YAML.stringify(cfg))
    setDirty(true)
  }, [])

  const scheduleValidation = useCallback((cfg: Record<string, any>) => {
    if (validateTimer.current) clearTimeout(validateTimer.current)
    validateTimer.current = setTimeout(async () => {
      try {
        const resp = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: YAML.stringify(cfg) })
        setValidationProblems(await resp.json())
      } catch { /* ignore */ }
    }, 800)
  }, [])
  scheduleValidationRef.current = scheduleValidation

  const save = useCallback(async (): Promise<boolean> => {
    setStatusText('Saving...')
    try {
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: yamlText })
      if (resp.ok) {
        setStatusText('Saved')
        setDirty(false)
        return true
      }
      if (resp.status === 422) {
        // Validation failed — update problems from response
        const errors = await resp.json()
        setValidationProblems(errors)
        setStatusText(`Save blocked: ${errors.length} validation error${errors.length > 1 ? 's' : ''}`)
        return false
      }
      setStatusText(`Save failed: ${await resp.text()}`)
      return false
    } catch {
      setStatusText('Save failed')
      return false
    }
  }, [yamlText])

  const reload = useCallback(async () => {
    setStatusText('Reloading...')
    try {
      const text = await fetchConfigText()
      setYamlTextState(text)
      try {
        setConfigState(YAML.parse(text) ?? {})
      } catch { setStatusText('Failed to parse YAML') }
      setDirty(false)
      setStatusText('Reloaded')
    } catch { setStatusText('Reload failed') }
  }, [])

  return (
    <ConfigContext.Provider value={{
      yamlText, setYamlText, setYamlTextRaw,
      config, setConfig, setConfigOnly,
      kindSchemas, allKinds,
      problems, scheduleValidation,
      dirty, setDirty,
      statusText, setStatusText,
      save, reload,
      loading,
      drefPaths,
      rawDefinitions,
      setExprError,
    }}>
      {children}
    </ConfigContext.Provider>
  )
}

/** Walk YAML AST and collect all dot-separated paths under Services */
function collectAstPaths(text: string): string[] {
  const result: string[] = []
  try {
    const doc = parseDocument(text)
    const root = doc.contents
    if (!isMap(root)) return result

    let servicesNode: any = null
    for (const pair of root.items) {
      if (isScalar(pair.key) && pair.key.value === 'Services' && isMap(pair.value)) {
        servicesNode = pair.value
        break
      }
    }
    if (!servicesNode) return result

    function walk(node: any, prefix: string) {
      if (isMap(node)) {
        for (const pair of node.items) {
          if (!isPair(pair) || !isScalar(pair.key)) continue
          const key = String(pair.key.value)
          const p = prefix ? `${prefix}.${key}` : key
          result.push(p)
          walk(pair.value, p)
        }
      } else if (isSeq(node)) {
        for (let i = 0; i < node.items.length; i++) {
          const item = node.items[i]
          if (isMap(item)) {
            let itemName: string | null = null
            for (const pair of item.items) {
              if (isPair(pair) && isScalar(pair.key) && String(pair.key.value) === 'name' && isScalar(pair.value)) {
                itemName = String(pair.value.value)
                break
              }
            }
            if (itemName) {
              const p = prefix ? `${prefix}.${itemName}` : itemName
              result.push(p)
              walk(item, p)
            } else {
              walk(item, `${prefix}[${i}]`)
            }
          }
        }
      }
    }
    walk(servicesNode, '')
  } catch {}
  return result
}
