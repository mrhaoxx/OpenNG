import { useEffect, useRef, useState, useCallback } from 'react'
import * as monaco from 'monaco-editor'
import { configureMonacoYaml } from 'monaco-yaml'
import { Button } from '@/components/ui/button'
import { csrfFetch } from '@/lib/api'
import { Save, RotateCw, Check, AlertCircle, AlertTriangle } from 'lucide-react'

// Configure Monaco workers
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import YamlWorker from 'monaco-yaml/yaml.worker?worker'

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

interface ConfigError {
  service: string
  kind: string
  phase: string
  message: string
  line?: number
}

interface Problem {
  source: 'server' | 'schema'
  phase: string
  service: string
  message: string
  line: number
  severity: 'error' | 'warning'
}

const PHASE_LABEL: Record<string, string> = {
  parse: 'Parse',
  schema: 'Schema',
  reference: 'Reference',
  type: 'Type',
  dependency: 'Dependency',
  yaml: 'YAML',
  jsonschema: 'Schema',
}

export default function Config() {
  const containerRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const [problems, setProblems] = useState<Problem[]>([])
  const [validating, setValidating] = useState(false)
  const [statusText, setStatusText] = useState('')
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const serverProblemsRef = useRef<Problem[]>([])
  const schemaProblemsRef = useRef<Problem[]>([])

  const mergeProblems = useCallback(() => {
    setProblems([...schemaProblemsRef.current, ...serverProblemsRef.current])
  }, [])

  // Run server-side validation and set markers on the editor
  const runValidation = useCallback(async () => {
    const content = editorRef.current?.getValue()
    if (!content) return
    setValidating(true)
    try {
      const resp = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: content })
      const errs: ConfigError[] = await resp.json()

      const model = editorRef.current?.getModel()
      const text = model?.getValue() ?? ''

      const serverProblems: Problem[] = errs.map(err => ({
        source: 'server' as const,
        phase: err.phase,
        service: err.service,
        message: err.message,
        line: findServiceLine(text, err.service),
        severity: 'error',
      }))
      serverProblemsRef.current = serverProblems

      // Set Monaco markers for server errors
      if (model) {
        const markers: monaco.editor.IMarkerData[] = serverProblems.map(p => ({
          severity: monaco.MarkerSeverity.Error,
          message: `[${PHASE_LABEL[p.phase] ?? p.phase}] ${p.message}`,
          startLineNumber: p.line,
          startColumn: 1,
          endLineNumber: p.line,
          endColumn: model.getLineMaxColumn(p.line),
          source: 'openng',
        }))
        monaco.editor.setModelMarkers(model, 'openng-validate', markers)
      }
    } catch {
      serverProblemsRef.current = []
    }
    mergeProblems()
    setValidating(false)
  }, [mergeProblems])

  // Debounced validation on content change
  const scheduleValidation = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(runValidation, 800)
  }, [runValidation])

  useEffect(() => {
    if (!containerRef.current) return

    const uri = monaco.Uri.parse('config.yaml')
    const model = monaco.editor.getModel(uri) ?? monaco.editor.createModel('# Loading...', 'yaml', uri)

    const editor = monaco.editor.create(containerRef.current, {
      language: 'yaml',
      theme: 'vs-dark',
      fontSize: 13,
      minimap: { enabled: false },
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      automaticLayout: true,
      tabSize: 2,
      wordWrap: 'on',
      model,
      quickSuggestions: { other: true, comments: false, strings: true },
      suggestOnTriggerCharacters: true,
      acceptSuggestionOnEnter: 'on',
      wordBasedSuggestions: 'currentDocument',
    })

    editorRef.current = editor

    fetch('/api/v1/cfg/get')
      .then(r => r.text())
      .then(text => {
        editor.getModel()?.setValue(text)
        runValidation()
      })
      .catch(() => setStatusText('Failed to load config'))

    const contentDisposable = editor.onDidChangeModelContent(scheduleValidation)

    // Listen for Monaco marker changes (JSON Schema / YAML syntax errors)
    const markerDisposable = monaco.editor.onDidChangeMarkers(([resource]) => {
      if (resource.toString() !== model.uri.toString()) return
      const allMarkers = monaco.editor.getModelMarkers({ resource })
      const schemaMarkers = allMarkers.filter(m => m.owner !== 'openng-validate')
      schemaProblemsRef.current = schemaMarkers.map(m => ({
        source: 'schema' as const,
        phase: m.severity === monaco.MarkerSeverity.Error ? 'jsonschema' : 'yaml',
        service: '',
        message: m.message,
        line: m.startLineNumber,
        severity: m.severity === monaco.MarkerSeverity.Error ? 'error' : 'warning',
      }))
      mergeProblems()
    })

    return () => {
      contentDisposable.dispose()
      markerDisposable.dispose()
      if (timerRef.current) clearTimeout(timerRef.current)
      editor.getModel()?.dispose()
      editor.dispose()
    }
  }, [runValidation, scheduleValidation, mergeProblems])

  const save = useCallback(async () => {
    const content = editorRef.current?.getValue()
    if (!content) return
    setStatusText('Saving...')
    try {
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: content })
      setStatusText(resp.ok ? 'Saved' : `Save failed: ${await resp.text()}`)
      if (resp.ok) runValidation()
    } catch {
      setStatusText('Save failed')
    }
  }, [runValidation])

  const reload = useCallback(async () => {
    setStatusText('Reloading...')
    try {
      const resp = await csrfFetch('/api/v1/cfg/reload', { method: 'POST' })
      setStatusText(resp.ok ? 'Config reloaded' : `Reload failed: ${await resp.text()}`)
    } catch {
      setStatusText('Reload failed')
    }
  }, [])

  const goToProblem = useCallback((p: Problem) => {
    const editor = editorRef.current
    if (!editor) return
    editor.revealLineInCenter(p.line)
    editor.setPosition({ lineNumber: p.line, column: 1 })
    editor.focus()
  }, [])

  const errorCount = problems.filter(p => p.severity === 'error').length
  const warnCount = problems.filter(p => p.severity === 'warning').length

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
        {statusText && (
          <span className="ml-auto text-xs text-muted-foreground">{statusText}</span>
        )}
      </div>

      {/* Editor */}
      <div ref={containerRef} className="flex-1 min-h-0" />

      {/* Problems panel */}
      <div className="shrink-0 border-t border-border bg-neutral-950">
        <div className="flex items-center gap-3 px-3 py-1 text-[11px]">
          <button
            className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => document.getElementById('problems-list')?.classList.toggle('hidden')}
          >
            {validating ? (
              <span className="text-muted-foreground">Validating...</span>
            ) : problems.length === 0 ? (
              <><Check size={12} className="text-green-500" /> No problems</>
            ) : (
              <>
                {errorCount > 0 && <><AlertCircle size={12} className="text-red-400" /> {errorCount}</>}
                {warnCount > 0 && <><AlertTriangle size={12} className="text-yellow-400 ml-1" /> {warnCount}</>}
              </>
            )}
          </button>
        </div>

        {problems.length > 0 && (
          <div id="problems-list" className="max-h-40 overflow-auto border-t border-neutral-800">
            {problems.map((p, i) => (
              <button
                key={i}
                onClick={() => goToProblem(p)}
                className="w-full text-left px-3 py-1 text-xs hover:bg-neutral-800/50 flex items-start gap-2 transition-colors"
              >
                {p.severity === 'error' ? (
                  <AlertCircle size={12} className="text-red-400 mt-0.5 shrink-0" />
                ) : (
                  <AlertTriangle size={12} className="text-yellow-400 mt-0.5 shrink-0" />
                )}
                <span className="text-muted-foreground shrink-0 w-16">{PHASE_LABEL[p.phase] ?? p.phase}</span>
                {p.service && (
                  <span className="text-foreground font-mono shrink-0">{p.service}</span>
                )}
                {p.line > 1 && (
                  <span className="text-muted-foreground/60 shrink-0">Ln {p.line}</span>
                )}
                <span className="text-muted-foreground truncate">{p.message}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function findServiceLine(text: string, serviceName: string): number {
  if (!serviceName) return 1
  const lines = text.split('\n')
  const pattern = new RegExp(`^  ${serviceName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`)
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return i + 1
  }
  return 1
}
