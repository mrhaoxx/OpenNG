import { useEffect, useCallback, useRef, useMemo } from 'react'
import * as monaco from 'monaco-editor'
import YAML from 'yaml'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Save, RotateCw } from 'lucide-react'
import { useConfig } from '@/lib/ConfigContext'
import { AssertForm } from '@/components/AssertForm'
import { parseDocument, isMap, isSeq, isPair, isScalar, type Document } from 'yaml'

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

type ChangeSource = 'yaml' | 'visual' | 'none'

export default function ConfigPage() {
  const { yamlText, setYamlText, setYamlTextRaw, config, setConfigOnly, kindSchemas, allKinds, problems, scheduleValidation, dirty, statusText, save, reload, drefPaths } = useConfig()
  const drefPathsRef = useRef(drefPaths)
  drefPathsRef.current = drefPaths
  const saveRef = useRef(save)
  saveRef.current = save
  const editorContainerRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const visualRef = useRef<HTMLDivElement>(null)
  const changeSourceRef = useRef<ChangeSource>('none')
  const yamlTextRef = useRef(yamlText)
  const suppressSaveRef = useRef(true) // suppress until first restore done

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

  // ── Monaco Editor (shared across code/split) ──

  useEffect(() => {
    if (!editorContainerRef.current) return
    const uri = monaco.Uri.parse('config.yaml')
    const model = monaco.editor.getModel(uri) ?? monaco.editor.createModel('', 'yaml', uri)
    const editor = monaco.editor.create(editorContainerRef.current, {
      language: 'yaml', theme: 'vs-dark', fontSize: 13,
      minimap: { enabled: false }, lineNumbers: 'on',
      scrollBeyondLastLine: false, automaticLayout: true,
      tabSize: 2, wordWrap: 'on', model,
      quickSuggestions: { other: true, comments: false, strings: true },
      suggestOnTriggerCharacters: true,
    })
    editorRef.current = editor

    // Ctrl+S in Monaco
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
      saveRef.current()
    })

    // Save scroll & cursor on changes (paused during restore)
    const scrollDisposable = editor.onDidScrollChange(() => {
      if (suppressSaveRef.current) return
      const pos = editor.getPosition()
      sessionStorage.setItem('ng-editor-state', JSON.stringify({
        scrollTop: editor.getScrollTop(), scrollLeft: editor.getScrollLeft(),
        lineNumber: pos?.lineNumber, column: pos?.column,
      }))
    })

    // $dref completion provider
    const completionDisposable = monaco.languages.registerCompletionItemProvider('yaml', {
      triggerCharacters: ['{', '.'],
      provideCompletionItems(model, position) {
        const lineContent = model.getLineContent(position.lineNumber)
        const textBefore = lineContent.substring(0, position.column - 1)
        // Match $dref{ or $dref{partial.path
        const drefMatch = textBefore.match(/\$dref\{([^}]*)$/)
        if (!drefMatch) return { suggestions: [] }
        const typed = drefMatch[1]
        const startCol = position.column - typed.length
        const range = new monaco.Range(position.lineNumber, startCol, position.lineNumber, position.column)
        const paths = drefPathsRef.current
        const lower = typed.toLowerCase()
        const filtered = typed ? paths.filter(p => p.toLowerCase().includes(lower)) : paths
        return {
          suggestions: filtered.slice(0, 30).map(p => ({
            label: p,
            kind: monaco.languages.CompletionItemKind.Reference,
            insertText: p,
            range,
            detail: '$dref path',
          })),
        }
      },
    })

    return () => { completionDisposable.dispose(); scrollDisposable.dispose(); editor.getModel()?.dispose(); editor.dispose() }
  }, [])

  // Ctrl+S to save
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        save()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [save])

  // Sync context yamlText → editor + restore position on first load
  const restoredRef = useRef(false)
  useEffect(() => {
    const editor = editorRef.current
    if (!editor) return
    if (yamlText !== yamlTextRef.current) {
      yamlTextRef.current = yamlText
      if (editor.getValue() !== yamlText) {
        changeSourceRef.current = 'yaml'
        editor.setValue(yamlText)
        setTimeout(() => { changeSourceRef.current = 'none' }, 50)
      }
      // Restore scroll & cursor on first real content load
      if (!restoredRef.current && yamlText.length > 0) {
        restoredRef.current = true
        const saved = sessionStorage.getItem('ng-editor-state')
        if (saved) {
          try {
            const { scrollTop, scrollLeft, lineNumber, column } = JSON.parse(saved)
            // Use double rAF to ensure Monaco has finished layout after setValue
            requestAnimationFrame(() => requestAnimationFrame(() => {
              editor.setScrollPosition({ scrollTop, scrollLeft })
              if (lineNumber) editor.setPosition({ lineNumber, column: column ?? 1 })
              suppressSaveRef.current = false
            }))
          } catch { suppressSaveRef.current = false }
        } else {
          suppressSaveRef.current = false
        }
      }
    }
  }, [yamlText])

  // Editor content changes → sync to context
  useEffect(() => {
    const editor = editorRef.current
    if (!editor) return
    const disposable = editor.onDidChangeModelContent(() => {
      if (changeSourceRef.current === 'visual') return
      if (changeSourceRef.current === 'yaml') return
      const text = editor.getValue()
      yamlTextRef.current = text
      // setYamlText already parses and updates config; scheduleValidation uses that
      setYamlText(text)
    })
    return () => disposable.dispose()
  }, [setYamlText, scheduleValidation])

  // Sidebar click → scroll editor to service
  useEffect(() => {
    const handler = (e: Event) => {
      const svcName = (e as CustomEvent).detail as string
      const editor = editorRef.current
      const model = editor?.getModel()
      if (!editor || !model) return
      const line = findYamlLine(model.getValue(), `svc-${svcName}`)
      if (line > 0) {
        editor.revealLineInCenter(line)
        editor.setPosition({ lineNumber: line, column: 1 })
        // Highlight YAML line
        const decs = editor.deltaDecorations([], [{
          range: new monaco.Range(line, 1, line, model.getLineMaxColumn(line)),
          options: { className: 'yaml-highlight-line', isWholeLine: true },
        }])
        setTimeout(() => editor.deltaDecorations(decs, []), 1500)
      }
      // Also scroll + highlight visual panel
      const el = visualRef.current?.querySelector<HTMLElement>(`[id="${CSS.escape(`svc-${svcName}`)}"]`)
      if (el) {
        el.scrollIntoView({ block: 'start' })
        el.classList.add('ring-1', 'ring-blue-500/40', 'rounded')
        setTimeout(() => el.classList.remove('ring-1', 'ring-blue-500/40', 'rounded'), 1500)
      }
    }
    window.addEventListener('ng-scroll-to-service', handler)
    return () => window.removeEventListener('ng-scroll-to-service', handler)
  }, [])

  // Restore visual scroll on first config load
  const visualRestoredRef = useRef(false)
  const suppressVisualSaveRef = useRef(true)
  useEffect(() => {
    if (!config || visualRestoredRef.current) return
    visualRestoredRef.current = true
    const panel = visualRef.current
    if (!panel) return
    const saved = sessionStorage.getItem('ng-visual-scroll')
    if (saved) {
      // Triple rAF: wait for React render + layout + paint
      requestAnimationFrame(() => requestAnimationFrame(() => requestAnimationFrame(() => {
        panel.scrollTop = parseFloat(saved)
        suppressVisualSaveRef.current = false
      })))
    } else {
      suppressVisualSaveRef.current = false
    }
  }, [config])

  // ── YAML cursor → Visual scroll ──

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

      const panel = visualRef.current
      if (!panel) return
      let el = panel.querySelector<HTMLElement>(`#${CSS.escape(targetId)}`)
      if (!el && fieldPath) {
        let p = fieldPath
        while (!el && p.includes('.')) {
          p = p.substring(0, p.lastIndexOf('.'))
          el = panel.querySelector<HTMLElement>(`#${CSS.escape(`field-${p}`)}`)
        }
        if (!el) el = panel.querySelector<HTMLElement>(`#${CSS.escape(`svc-${svc}`)}`)
      }
      if (el) {
        const rect = el.getBoundingClientRect()
        const panelRect = panel.getBoundingClientRect()
        const inView = rect.top >= panelRect.top && rect.bottom <= panelRect.bottom
        el.scrollIntoView({ block: inView ? 'nearest' : 'center' })
        el.classList.add('ring-1', 'ring-blue-500/40', 'rounded')
        setTimeout(() => el.classList.remove('ring-1', 'ring-blue-500/40', 'rounded'), 1200)
      }
    })
    return () => disposable.dispose()
  }, [])

  // ── Visual focus → YAML scroll ──

  const visualFocusTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    const panel = visualRef.current
    if (!panel) return
    const handler = (e: FocusEvent) => {
      if (visualFocusTimer.current) clearTimeout(visualFocusTimer.current)
      visualFocusTimer.current = setTimeout(() => handleVisualFocus(e), 100)
    }
    const handleVisualFocus = (e: FocusEvent) => {
      if (changeSourceRef.current === 'visual') return
      const editor = editorRef.current
      const model = editor?.getModel()
      if (!editor || !model) return

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
        const visibleRanges = editor.getVisibleRanges()
        const isVisible = visibleRanges.some(r => line >= r.startLineNumber && line <= r.endLineNumber)
        if (!isVisible) editor.revealLineInCenter(line)
        const decs = editor.deltaDecorations([], [{
          range: new monaco.Range(line, 1, line, model.getLineMaxColumn(line)),
          options: { className: 'yaml-highlight-line', isWholeLine: true },
        }])
        setTimeout(() => editor.deltaDecorations(decs, []), 1500)
      }
    }
    panel.addEventListener('focusin', handler)
    return () => {
      panel.removeEventListener('focusin', handler)
      if (visualFocusTimer.current) clearTimeout(visualFocusTimer.current)
    }
  }, [])

  // ── Visual → YAML sync ──

  const updateFromVisual = useCallback((next: Record<string, any>) => {
    changeSourceRef.current = 'visual'
    setConfigOnly(next)
    const text = YAML.stringify(next)
    yamlTextRef.current = text
    // Update context yamlText without re-parsing (we already have the config)
    setYamlTextRaw(text)
    const editor = editorRef.current
    if (editor) {
      const model = editor.getModel()
      if (model && model.getValue() !== text) {
        const pos = editor.getPosition()
        model.setValue(text)
        if (pos) editor.setPosition(pos)
      }
    }
    setTimeout(() => { changeSourceRef.current = 'none' }, 50)
    scheduleValidation(next)
  }, [setConfigOnly, setYamlTextRaw, scheduleValidation])

  const updateService = useCallback((name: string, value: Record<string, any>) => {
    if (!config) return
    updateFromVisual({ ...config, Services: { ...config.Services, [name]: value } })
  }, [config, updateFromVisual])

  // ── Layout ──


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

      {/* Editor + Visual */}
      <div className="flex-1 flex min-h-0">
        <div ref={editorContainerRef} className="flex-1 min-w-0" />
        <div className="w-px bg-neutral-800 shrink-0" />
        <div ref={visualRef} className="flex-1 min-w-0 overflow-y-auto" onScroll={(e) => {
          if (!suppressVisualSaveRef.current) {
            sessionStorage.setItem('ng-visual-scroll', String((e.target as HTMLElement).scrollTop))
          }
        }}>
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
                  visualRef.current?.querySelector<HTMLElement>(`[id="${CSS.escape(`svc-${p.service}`)}"]`)?.scrollIntoView({ block: 'start' })
                  const editor = editorRef.current
                  const model = editor?.getModel()
                  if (editor && model) {
                    const line = findYamlLine(model.getValue(), `svc-${p.service}`)
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

// ── AST-based YAML ↔ field path mapping ──

function offsetToLine(text: string, offset: number): number {
  let line = 1
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') line++
  }
  return line
}

let _cachedText = ''
let _cachedDoc: Document.Parsed | null = null
function getDoc(text: string): Document.Parsed {
  if (text !== _cachedText) {
    _cachedText = text
    _cachedDoc = parseDocument(text, { keepSourceTokens: true })
  }
  return _cachedDoc!
}

function getServicesMap(doc: Document.Parsed): any {
  const root = doc.contents
  if (!isMap(root)) return null
  for (const pair of root.items) {
    if (isScalar(pair.key) && pair.key.value === 'Services' && isMap(pair.value)) {
      return pair.value
    }
  }
  return null
}

function serviceAtLine(text: string, line: number): string | null {
  const doc = getDoc(text)
  const svcMap = getServicesMap(doc)
  if (!svcMap) return null
  let offset = 0
  for (let l = 1; l < line && offset < text.length; l++) {
    offset = text.indexOf('\n', offset) + 1
  }
  let result: string | null = null
  for (const pair of svcMap.items) {
    if (!isPair(pair) || !isScalar(pair.key)) continue
    const range = (pair.key as any).range ?? (pair.value as any)?.range
    if (range && range[0] <= offset) result = String(pair.key.value)
  }
  return result
}

function buildFieldPath(text: string, line: number, svc: string): string | null {
  const doc = getDoc(text)
  const svcMap = getServicesMap(doc)
  if (!svcMap) return null
  let offset = 0
  for (let l = 1; l < line && offset < text.length; l++) {
    offset = text.indexOf('\n', offset) + 1
  }
  const nextNl = text.indexOf('\n', offset)
  if (nextNl > offset) offset = Math.floor((offset + nextNl) / 2)

  let svcNode: any = null
  for (const pair of svcMap.items) {
    if (isPair(pair) && isScalar(pair.key) && String(pair.key.value) === svc) {
      svcNode = pair.value
      break
    }
  }
  if (!svcNode) return null

  const segments: string[] = []
  function walk(node: any): boolean {
    if (!node || !node.range) return false
    const [start, , end] = node.range
    if (offset < start || offset >= end) return false
    if (isMap(node)) {
      for (const pair of node.items) {
        if (!isPair(pair) || !isScalar(pair.key)) continue
        const key = String(pair.key.value)
        const pairStart = (pair.key as any).range?.[0] ?? 0
        const pairEnd = (pair.value as any)?.range?.[2] ?? (pair.key as any).range?.[2] ?? 0
        if (offset >= pairStart && offset < pairEnd) {
          if (key !== 'kind') segments.push(key)
          walk(pair.value)
          return true
        }
      }
      return true
    }
    if (isSeq(node)) {
      for (let i = 0; i < node.items.length; i++) {
        const item = node.items[i] as any
        if (!item?.range) continue
        const [iStart, , iEnd] = item.range
        if (offset >= iStart && offset < iEnd) {
          segments.push(`[${i}]`)
          walk(item)
          return true
        }
      }
      return true
    }
    return true
  }

  walk(svcNode)
  if (segments.length === 0) return null
  let path = svc
  for (const seg of segments) {
    path += seg.startsWith('[') ? seg : '.' + seg
  }
  return path
}

function findYamlLine(text: string, elementId: string): number {
  const doc = getDoc(text)
  const svcMap = getServicesMap(doc)
  if (!svcMap) return 1

  if (elementId.startsWith('svc-')) {
    const name = elementId.slice(4)
    for (const pair of svcMap.items) {
      if (isPair(pair) && isScalar(pair.key) && String(pair.key.value) === name) {
        return offsetToLine(text, (pair.key as any).range[0])
      }
    }
    return 1
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

  let node: any = svcMap
  let lastOffset = 0
  for (const seg of segments) {
    if (!node) break
    if (seg.startsWith('[')) {
      const idx = parseInt(seg.slice(1, -1))
      if (isSeq(node) && idx < node.items.length) {
        const item = node.items[idx] as any
        if (item?.range) lastOffset = item.range[0]
        node = item
      } else break
    } else {
      if (isMap(node)) {
        let found = false
        for (const pair of node.items) {
          if (isPair(pair) && isScalar(pair.key) && String(pair.key.value) === seg) {
            lastOffset = (pair.key as any).range[0]
            node = pair.value
            found = true
            break
          }
        }
        if (!found) break
      } else break
    }
  }
  return lastOffset > 0 ? offsetToLine(text, lastOffset) : 1
}
