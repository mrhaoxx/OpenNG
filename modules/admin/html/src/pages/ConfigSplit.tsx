import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import * as monaco from 'monaco-editor'
import YAML from 'yaml'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Save, RotateCw } from 'lucide-react'
import { fetchSchema, fetchConfigText, csrfFetch } from '@/lib/api'
import { parseKindSchemas, allKindNames } from '@/lib/schema'
import type { KindSchema } from '@/lib/schema'
import { AssertForm } from '@/components/AssertForm'

import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import YamlWorker from 'monaco-yaml/yaml.worker?worker'
import { configureMonacoYaml } from 'monaco-yaml'

if (!self.MonacoEnvironment) {
  self.MonacoEnvironment = {
    getWorker(_, label) {
      if (label === 'yaml') return new YamlWorker()
      return new EditorWorker()
    },
  }
  configureMonacoYaml(monaco, {
    enableSchemaRequest: true,
    schemas: [{
      uri: new URL('/api/v1/cfg/schema', window.location.origin).href,
      fileMatch: ['config.yaml'],
    }],
  })
}

interface ConfigError { service: string; kind: string; phase: string; message: string }

type ChangeSource = 'yaml' | 'visual' | 'none'

export default function ConfigSplit() {
  const editorContainerRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const visualRef = useRef<HTMLDivElement>(null)
  const [config, setConfig] = useState<Record<string, any> | null>(null)
  const [kindSchemas, setKindSchemas] = useState<Map<string, KindSchema>>(new Map())
  const [problems, setProblems] = useState<ConfigError[]>([])
  const [dirty, setDirty] = useState(false)
  const [statusText, setStatusText] = useState('')
  const changeSourceRef = useRef<ChangeSource>('none')
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

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

  // Load schema + config
  useEffect(() => {
    Promise.all([fetchSchema(), fetchConfigText()])
      .then(([schemaData, yamlText]) => {
        setKindSchemas(parseKindSchemas(schemaData))
        try { setConfig(YAML.parse(yamlText) ?? {}) } catch { setStatusText('Failed to parse YAML') }
      })
      .catch(() => setStatusText('Failed to load'))
  }, [])

  // Create Monaco editor
  useEffect(() => {
    if (!editorContainerRef.current) return
    const uri = monaco.Uri.parse('config.yaml')
    const model = monaco.editor.getModel(uri) ?? monaco.editor.createModel('# Loading...', 'yaml', uri)
    const editor = monaco.editor.create(editorContainerRef.current, {
      language: 'yaml', theme: 'vs-dark', fontSize: 13,
      minimap: { enabled: false }, lineNumbers: 'on',
      scrollBeyondLastLine: false, automaticLayout: true,
      tabSize: 2, wordWrap: 'on', model,
      quickSuggestions: { other: true, comments: false, strings: true },
      suggestOnTriggerCharacters: true,
    })
    editorRef.current = editor
    fetchConfigText().then(text => editor.getModel()?.setValue(text)).catch(() => {})
    return () => { editor.getModel()?.dispose(); editor.dispose() }
  }, [])

  // YAML → Visual sync
  useEffect(() => {
    const editor = editorRef.current
    if (!editor) return
    const disposable = editor.onDidChangeModelContent(() => {
      if (changeSourceRef.current === 'visual') return
      const text = editor.getValue()
      setDirty(true)
      try {
        const parsed = YAML.parse(text)
        if (parsed) {
          changeSourceRef.current = 'yaml'
          setConfig(parsed)
          setTimeout(() => { changeSourceRef.current = 'none' }, 50)
          scheduleValidation(parsed)
        }
      } catch { /* invalid YAML */ }
    })
    return () => disposable.dispose()
  }, [])

  // Sidebar click → scroll Monaco to service
  useEffect(() => {
    const handler = (e: Event) => {
      const svcName = (e as CustomEvent).detail as string
      const editor = editorRef.current
      const model = editor?.getModel()
      if (!editor || !model) return
      const line = findServiceLine(model.getValue(), svcName)
      if (line > 0) {
        editor.revealLineInCenter(line)
        editor.setPosition({ lineNumber: line, column: 1 })
      }
    }
    window.addEventListener('ng-scroll-to-service', handler)
    return () => window.removeEventListener('ng-scroll-to-service', handler)
  }, [])

  // YAML cursor → scroll visual to matching field
  useEffect(() => {
    const editor = editorRef.current
    if (!editor) return
    let prevTarget = ''
    const disposable = editor.onDidChangeCursorPosition((e) => {
      const model = editor.getModel()
      if (!model) return
      const text = model.getValue()
      const svc = serviceAtLine(text, e.position.lineNumber)
      if (!svc) return

      const fieldPath = buildFieldPath(text, e.position.lineNumber, svc)
      const targetId = fieldPath ? `field-${fieldPath}` : `svc-${svc}`
      if (targetId === prevTarget) return
      prevTarget = targetId

      // Try exact match, then walk up the path to find closest element
      let el = document.getElementById(targetId)
      if (!el && fieldPath) {
        let p = fieldPath
        while (!el && p.includes('.')) {
          p = p.substring(0, p.lastIndexOf('.'))
          el = document.getElementById(`field-${p}`)
        }
        if (!el) el = document.getElementById(`svc-${svc}`)
      }
      if (el) {
        const rect = el.getBoundingClientRect()
        const panel = visualRef.current
        if (panel) {
          const panelRect = panel.getBoundingClientRect()
          const inView = rect.top >= panelRect.top && rect.bottom <= panelRect.bottom
          el.scrollIntoView({ block: inView ? 'nearest' : 'center' })
        } else {
          el.scrollIntoView({ block: 'nearest' })
        }
        el.classList.add('ring-1', 'ring-blue-500/40', 'rounded')
        setTimeout(() => el.classList.remove('ring-1', 'ring-blue-500/40', 'rounded'), 1200)
      }
    })
    return () => disposable.dispose()
  }, [])

  // Visual focus → scroll YAML to matching line (debounced)
  const configReady = config !== null
  const visualFocusTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    const panel = visualRef.current
    if (!panel) return
    const handler = (e: FocusEvent) => {
      if (visualFocusTimer.current) clearTimeout(visualFocusTimer.current)
      visualFocusTimer.current = setTimeout(() => handleVisualFocus(e), 100)
    }
    const handleVisualFocus = (e: FocusEvent) => {
      const editor = editorRef.current
      const model = editor?.getModel()
      if (!editor || !model) return

      // Walk up from focused element to find a field-* or svc-* id
      let el = e.target as HTMLElement | null
      let fieldId = ''
      while (el && el !== panel) {
        if (el.id?.startsWith('field-') || el.id?.startsWith('svc-')) {
          fieldId = el.id
          break
        }
        el = el.parentElement
      }
      if (!fieldId) return

      const text = model.getValue()
      const line = findYamlLine(text, fieldId)
      if (line > 0) {
        editor.revealLineInCenter(line)
        // Highlight the line briefly
        const decs = editor.deltaDecorations([], [{
          range: new monaco.Range(line, 1, line, model.getLineMaxColumn(line)),
          options: { className: 'yaml-highlight-line', isWholeLine: true },
        }])
        setTimeout(() => editor.deltaDecorations(decs, []), 1500)
      }
    } // end handleVisualFocus
    panel.addEventListener('focusin', handler)
    return () => {
      panel.removeEventListener('focusin', handler)
      if (visualFocusTimer.current) clearTimeout(visualFocusTimer.current)
    }
  }, [configReady])

  // Visual → YAML sync
  const updateFromVisual = useCallback((next: Record<string, any>) => {
    changeSourceRef.current = 'visual'
    setConfig(next)
    setDirty(true)
    const editor = editorRef.current
    if (editor) {
      const yamlText = YAML.stringify(next, { indent: 2 })
      const model = editor.getModel()
      if (model && model.getValue() !== yamlText) {
        const pos = editor.getPosition()
        model.setValue(yamlText)
        if (pos) editor.setPosition(pos)
      }
    }
    setTimeout(() => { changeSourceRef.current = 'none' }, 50)
    scheduleValidation(next)
  }, [])

  const updateService = useCallback((name: string, value: Record<string, any>) => {
    if (!config) return
    updateFromVisual({ ...config, Services: { ...config.Services, [name]: value } })
  }, [config, updateFromVisual])

  const scheduleValidation = useRef((cfg: Record<string, any>) => {
    if (validateTimer.current) clearTimeout(validateTimer.current)
    validateTimer.current = setTimeout(async () => {
      try {
        const resp = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: YAML.stringify(cfg) })
        setProblems(await resp.json())
      } catch { /* ignore */ }
    }, 800)
  }).current

  const save = useCallback(async () => {
    const editor = editorRef.current
    if (!editor) return
    setStatusText('Saving...')
    try {
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: editor.getValue() })
      setStatusText(resp.ok ? 'Saved' : `Save failed: ${await resp.text()}`)
      if (resp.ok) setDirty(false)
    } catch { setStatusText('Save failed') }
  }, [])

  const reload = useCallback(async () => {
    setStatusText('Reloading...')
    try {
      const text = await fetchConfigText()
      editorRef.current?.getModel()?.setValue(text)
      setConfig(YAML.parse(text) ?? {})
      setDirty(false)
      setStatusText('Reloaded')
    } catch { setStatusText('Reload failed') }
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

      {/* Split view */}
      <div className="flex-1 flex min-h-0">
        {/* Left: Monaco */}
        <div ref={editorContainerRef} className="flex-1 min-w-0" />
        <div className="w-px bg-neutral-800 shrink-0" />

        {/* Right: Visual waterfall */}
        <div ref={visualRef} className="flex-1 min-w-0 overflow-y-auto">
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
                        {/* Service header */}
                        <div className="flex items-center gap-2 mb-3 sticky top-0 bg-background/90 backdrop-blur-sm py-1 z-10">
                          <span className="text-base font-semibold font-mono">{name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400">{kind}</span>
                          {svcProblems.length > 0 && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">
                              {svcProblems.length} error{svcProblems.length > 1 ? 's' : ''}
                            </span>
                          )}
                        </div>

                        {/* Kind selector */}
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

                        {/* Fields from schema */}
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

                        {/* Problems */}
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
        {problems.length > 0 && (
          <div className="max-h-32 overflow-auto border-t border-neutral-800">
            {problems.map((p, i) => (
              <button
                key={i}
                onClick={() => {
                  // Scroll both panels to the error's service
                  document.getElementById(`svc-${p.service}`)?.scrollIntoView({ block: 'start' })
                  const editor = editorRef.current
                  const model = editor?.getModel()
                  if (editor && model) {
                    const line = findServiceLine(model.getValue(), p.service)
                    if (line > 0) editor.revealLineInCenter(line)
                  }
                }}
                className="w-full text-left px-3 py-1 text-xs hover:bg-neutral-800/50 flex items-start gap-2 transition-colors"
              >
                <span className="text-red-400 mt-0.5 shrink-0">✗</span>
                <span className="text-muted-foreground shrink-0 w-14">{p.phase}</span>
                {p.service && <span className="text-foreground font-mono shrink-0">{p.service}</span>}
                <span className="text-muted-foreground truncate">{p.message}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/** Find the YAML line where a service is defined */
function findServiceLine(text: string, serviceName: string): number {
  const lines = text.split('\n')
  const pattern = new RegExp(`^  ${serviceName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`)
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return i + 1
  }
  return 1
}

/** Find which service the cursor line is inside */
function serviceAtLine(text: string, line: number): string | null {
  const lines = text.split('\n')
  const pat = /^  (\S+)\s*:/
  let result: string | null = null
  for (let i = 0; i < lines.length && i < line; i++) {
    const m = lines[i].match(pat)
    if (m) result = m[1]
  }
  return result
}

/**
 * Build the full field path from a YAML cursor position.
 * Returns paths like "httpproxier.hosts[7].backend" matching DOM element ids.
 */
function buildFieldPath(text: string, line: number, svc: string): string | null {
  const lines = text.split('\n')
  if (line < 1 || line > lines.length) return null

  // Collect path segments walking upward from cursor line
  // We unshift (prepend) so segments end up in top-to-bottom order
  const segments: string[] = []
  let curIndent = Infinity

  for (let i = line - 1; i >= 0; i--) {
    const raw = lines[i]
    const trimmed = raw.trimStart()
    if (!trimmed || trimmed.startsWith('#')) continue
    const indent = raw.length - trimmed.length

    if (indent >= curIndent) continue
    if (indent <= 2) break // reached service name level or above

    if (trimmed.startsWith('- ')) {
      // List item — count index by counting "- " at same indent going upward
      let idx = 0
      for (let j = i - 1; j >= 0; j--) {
        const jr = lines[j]
        const jt = jr.trimStart()
        const ji = jr.length - jt.length
        if (ji < indent) break
        if (ji === indent && jt.startsWith('- ')) idx++
      }
      segments.unshift(`[${idx}]`)
    } else {
      const keyMatch = trimmed.match(/^(\S+)\s*:/)
      if (keyMatch) {
        segments.unshift(keyMatch[1])
      }
    }

    curIndent = indent
  }

  // Add the current line's key if present
  const curTrimmed = lines[line - 1].trimStart()
  const curKey = curTrimmed.match(/^-?\s*(\S+)\s*:/)
  if (curKey) {
    const key = curKey[1]
    // Avoid duplicating if it was already picked up
    const last = segments[segments.length - 1]
    if (last !== key && key !== 'kind') {
      segments.push(key)
    }
  }

  if (segments.length === 0) return null

  // Build path: svc.field[0].subfield
  let path = svc
  for (const seg of segments) {
    if (seg.startsWith('[')) {
      path += seg
    } else {
      path += '.' + seg
    }
  }
  return path
}

/**
 * Given a DOM element id like "field-httpproxier.hosts[7].backend" or "svc-httpproxier",
 * find the corresponding YAML line number.
 */
function findYamlLine(text: string, elementId: string): number {
  if (elementId.startsWith('svc-')) {
    return findServiceLine(text, elementId.slice(4))
  }

  const path = elementId.slice('field-'.length)
  const segments: string[] = []
  let buf = ''
  for (const ch of path) {
    if (ch === '.' || ch === '[') {
      if (buf) segments.push(buf)
      buf = ch === '[' ? '[' : ''
    } else if (ch === ']') {
      segments.push(buf + ']')
      buf = ''
    } else {
      buf += ch
    }
  }
  if (buf) segments.push(buf)

  if (segments.length === 0) return 1

  const lines = text.split('\n')
  let lineIdx = 0
  let expectIndent = 0 // expected indent for next segment

  for (let si = 0; si < segments.length; si++) {
    const seg = segments[si]

    if (seg.startsWith('[')) {
      // List index: "- " items appear at expectIndent (same level as parent key's content)
      const idx = parseInt(seg.slice(1, -1))
      const listIndent = expectIndent
      let count = 0
      let found = false
      for (let i = lineIdx + 1; i < lines.length; i++) {
        const raw = lines[i]
        const trimmed = raw.trimStart()
        const indent = raw.length - trimmed.length
        if (indent < expectIndent && trimmed) break
        if (indent === listIndent && trimmed.startsWith('- ')) {
          if (count === idx) { lineIdx = i; expectIndent = listIndent + 2; found = true; break }
          count++
        }
      }
      if (!found) break
    } else {
      // Key: find "seg:" within current scope
      const escaped = seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const keyPat = new RegExp(`^-?\\s*${escaped}\\s*:`)
      let found = false
      for (let i = lineIdx + (si === 0 ? 0 : 1); i < lines.length; i++) {
        const raw = lines[i]
        const trimmed = raw.trimStart()
        if (!trimmed) continue
        const indent = raw.length - trimmed.length
        // Left the parent scope — key doesn't exist here
        if (i > lineIdx && indent <= expectIndent - 2 && si > 0) break
        if (indent >= expectIndent && indent <= expectIndent + 2 && keyPat.test(trimmed)) {
          lineIdx = i
          expectIndent = indent + 2
          found = true
          break
        }
      }
      if (!found) break
    }
  }

  return lineIdx + 1
}
