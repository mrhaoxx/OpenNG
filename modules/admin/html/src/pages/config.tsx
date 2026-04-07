import { useEffect, useRef, useState, useCallback } from 'react'
import * as monaco from 'monaco-editor'
import { configureMonacoYaml } from 'monaco-yaml'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { csrfFetch } from '@/lib/api'
import { Save, RotateCw, Check, AlertCircle } from 'lucide-react'

// Configure Monaco workers
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import YamlWorker from 'monaco-yaml/yaml.worker?worker'

self.MonacoEnvironment = {
  getWorker(_, label) {
    if (label === 'yaml') return new YamlWorker()
    return new EditorWorker()
  },
}

// Configure YAML schema
configureMonacoYaml(monaco, {
  enableSchemaRequest: true,
  schemas: [{
    uri: new URL('/api/v1/cfg/schema', window.location.origin).href,
    fileMatch: ['config.yaml'],
  }],
})

export default function Config() {
  const containerRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const [status, setStatus] = useState<{ text: string; variant: 'default' | 'success' | 'error' }>({ text: '', variant: 'default' })

  useEffect(() => {
    if (!containerRef.current) return

    const uri = monaco.Uri.parse('config.yaml')
    // Reuse existing model on remount to avoid "model already exists" error
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
        setStatus({ text: 'Config loaded', variant: 'success' })
      })
      .catch(() => setStatus({ text: 'Failed to load', variant: 'error' }))

    return () => {
      editor.getModel()?.dispose()
      editor.dispose()
    }
  }, [])

  const save = useCallback(async () => {
    const content = editorRef.current?.getValue()
    if (!content) return
    setStatus({ text: 'Saving...', variant: 'default' })
    try {
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: content })
      setStatus(resp.ok ? { text: 'Saved', variant: 'success' } : { text: `Save failed: ${await resp.text()}`, variant: 'error' })
    } catch {
      setStatus({ text: 'Save failed', variant: 'error' })
    }
  }, [])

  const validate = useCallback(async () => {
    const content = editorRef.current?.getValue()
    if (!content) return
    setStatus({ text: 'Validating...', variant: 'default' })
    try {
      const resp = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: content })
      const text = await resp.text()
      setStatus(text === 'ok' ? { text: 'Valid', variant: 'success' } : { text, variant: 'error' })
    } catch {
      setStatus({ text: 'Validation failed', variant: 'error' })
    }
  }, [])

  const reload = useCallback(async () => {
    setStatus({ text: 'Reloading...', variant: 'default' })
    try {
      const resp = await csrfFetch('/api/v1/cfg/reload', { method: 'POST' })
      setStatus(resp.ok ? { text: 'Config reloaded', variant: 'success' } : { text: `Reload failed: ${await resp.text()}`, variant: 'error' })
    } catch {
      setStatus({ text: 'Reload failed', variant: 'error' })
    }
  }, [])

  return (
    <div className="h-full flex flex-col">
      <div className="shrink-0 flex items-center gap-2 px-4 py-2 border-b border-border bg-card">
        <h1 className="text-sm font-semibold mr-4">Configuration</h1>
        <Button size="sm" variant="outline" onClick={save} className="gap-1.5">
          <Save size={14} /> Save
        </Button>
        <Button size="sm" variant="outline" onClick={validate} className="gap-1.5">
          <Check size={14} /> Validate
        </Button>
        <Button size="sm" variant="outline" onClick={reload} className="gap-1.5">
          <RotateCw size={14} /> Reload
        </Button>
        {status.text && (
          <Badge
            variant={status.variant === 'error' ? 'destructive' : status.variant === 'success' ? 'default' : 'secondary'}
            className="ml-auto gap-1 text-xs"
          >
            {status.variant === 'error' && <AlertCircle size={12} />}
            {status.variant === 'success' && <Check size={12} />}
            {status.text}
          </Badge>
        )}
      </div>
      <div ref={containerRef} className="flex-1 min-h-0" />
    </div>
  )
}
