import { useEffect, useRef, useState } from 'preact/hooks'
import { csrfFetch } from '../api'

// Monaco is loaded imperatively to avoid circular imports
declare const window: Window & {
  MonacoEnvironment?: any
}

export function Config() {
  const containerRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<any>(null)
  const [status, setStatus] = useState('Loading editor...')
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let disposed = false

    async function init() {
      // Dynamic imports to avoid loading Monaco upfront
      const monaco = await import('monaco-editor')
      const { configureMonacoYaml } = await import('monaco-yaml')
      const { parseDocument, LineCounter, isMap, isSeq } = await import('yaml')

      if (disposed || !containerRef.current) return

      window.MonacoEnvironment = {
        getWorker(_moduleId: string, label: string) {
          switch (label) {
            case 'editorWorkerService':
              return new Worker(new URL('monaco-editor/esm/vs/editor/editor.worker', import.meta.url))
            case 'yaml':
              return new Worker(new URL('monaco-yaml/yaml.worker', import.meta.url))
            default:
              throw new Error(`Unknown label ${label}`)
          }
        }
      }

      configureMonacoYaml(monaco as any, {
        enableSchemaRequest: true,
        schemas: [{ uri: '/api/v1/cfg/schema', fileMatch: ['config.yaml'] }]
      })

      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      const ed = monaco.editor.create(containerRef.current, {
        automaticLayout: true,
        model: monaco.editor.createModel('# Loading config...', 'yaml', monaco.Uri.parse('config.yaml')),
        theme: isDark ? 'vs-dark' : 'vs-light',
        quickSuggestions: { other: true, comments: false, strings: true },
        formatOnType: true
      })

      editorRef.current = ed

      // Dark mode sync
      const mql = window.matchMedia('(prefers-color-scheme: dark)')
      const onDarkChange = (e: MediaQueryListEvent) => {
        monaco.editor.setTheme(e.matches ? 'vs-dark' : 'vs-light')
      }
      mql.addEventListener('change', onDarkChange)

      // Ctrl+S save
      ed.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => save())

      // Server validation
      let validationTimer: number | undefined
      let lastRequestId = 0

      function getServicesPositions(text: string): Array<{ line: number; column: number }> {
        try {
          const lc = new LineCounter()
          const doc = parseDocument(text, { lineCounter: lc })
          const root = doc.contents as any
          if (!root || !isMap(root)) return []
          const pair = root.items.find((it: any) => it.key?.value === 'Services')
          if (!pair) return []
          const seq = pair.value as any
          if (!seq || !isSeq(seq) || !Array.isArray(seq.items)) return []
          return seq.items.map((node: any) => {
            const startOffset = node?.range?.[0] ?? 0
            const pos = lc.linePos(startOffset)
            return { line: pos.line, column: pos.col }
          })
        } catch {
          return []
        }
      }

      async function runServerValidation(requestId: number) {
        try {
          const response = await csrfFetch('/api/v1/cfg/validate', { method: 'POST', body: ed.getValue() })
          const text = (await response.text()).trim()
          if (requestId !== lastRequestId) return
          const model = ed.getModel()
          if (!model) return

          if (text === 'ok') {
            monaco.editor.setModelMarkers(model, 'server-validate', [])
            return
          }

          const lines = text.split('\n').filter(Boolean)
          const svcPositions = getServicesPositions(ed.getValue())
          const markers = lines.map((msg: string) => {
            const m = msg.match(/^\[(\d+)\]\s?/)
            if (m) {
              const idx = parseInt(m[1], 10)
              const pos = svcPositions[idx]
              if (pos) {
                return {
                  severity: monaco.MarkerSeverity.Error,
                  message: msg,
                  startLineNumber: pos.line,
                  startColumn: pos.column,
                  endLineNumber: pos.line,
                  endColumn: pos.column + 1
                }
              }
            }
            return {
              severity: monaco.MarkerSeverity.Error,
              message: msg,
              startLineNumber: 1, startColumn: 1,
              endLineNumber: 1, endColumn: 1
            }
          })
          monaco.editor.setModelMarkers(model, 'server-validate', markers)
        } catch (e) {
          const model = ed.getModel()
          if (!model) return
          monaco.editor.setModelMarkers(model, 'server-validate', [{
            severity: monaco.MarkerSeverity.Error,
            message: (e as Error).message || 'Validation failed',
            startLineNumber: 1, startColumn: 1,
            endLineNumber: 1, endColumn: 1
          }])
        }
      }

      ed.onDidChangeModelContent(() => {
        if (validationTimer) clearTimeout(validationTimer)
        validationTimer = window.setTimeout(() => {
          lastRequestId++
          runServerValidation(lastRequestId)
        }, 120)
      })

      setStatus('Monaco ready')
      setReady(true)

      // Load config
      loadConfig()

      return () => {
        mql.removeEventListener('change', onDarkChange)
        ed.dispose()
      }
    }

    const cleanup = init()
    return () => {
      disposed = true
      cleanup.then(fn => fn?.())
    }
  }, [])

  async function loadConfig() {
    try {
      setStatus('Loading config...')
      const resp = await fetch('/api/v1/cfg/get')
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const text = await resp.text()
      editorRef.current?.setValue(text)
      setStatus(`Config loaded (${text.length} chars) — ${new Date().toISOString()}`)
    } catch (e) {
      setStatus(`Error: ${(e as Error).message}`)
    }
  }

  async function save() {
    if (!editorRef.current) return
    try {
      setStatus('Saving...')
      const resp = await csrfFetch('/api/v1/cfg/save', { method: 'POST', body: editorRef.current.getValue() })
      setStatus(`Saved: ${resp.statusText} — ${new Date().toISOString()}`)
    } catch (e) {
      setStatus(`Save error: ${(e as Error).message}`)
    }
  }

  async function reload() {
    await save()
    try {
      setStatus('Reloading...')
      const resp = await csrfFetch('/api/v1/cfg/reload', { method: 'POST' })
      if (resp.status !== 202) {
        const text = await resp.text()
        alert(text)
        setStatus(`Reload failed: ${text}`)
      } else {
        setStatus('Config reloaded successfully')
      }
    } catch (e) {
      setStatus(`Reload error: ${(e as Error).message}`)
    }
  }

  async function shutdown() {
    if (!confirm('Shutdown NetGATE?')) return
    try {
      const resp = await csrfFetch('/shutdown', { method: 'POST' })
      alert(`Status: ${resp.status}`)
    } catch {
      alert('Request failed')
    }
  }

  async function genHash() {
    const input = prompt('Text to hash:')
    if (!input) return
    try {
      const resp = await csrfFetch('/genhash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: input
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const hash = await resp.text()
      prompt('Hash result:', hash)
    } catch (e) {
      alert((e as Error).message)
    }
  }

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 shrink-0">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Config Editor</h1>
      </div>
      <div class="flex-1 min-h-0 flex flex-col p-4 gap-2">
        <div class="text-xs font-mono text-neutral-500 dark:text-neutral-400 px-1">{status}</div>
        <div ref={containerRef} class="flex-1 min-h-0 border border-neutral-200 dark:border-neutral-700 rounded overflow-hidden" />
        <div class="flex gap-2 flex-wrap shrink-0 pt-1">
          <button
            onClick={loadConfig}
            class="px-3 py-1.5 rounded bg-neutral-800 text-white dark:bg-neutral-200 dark:text-neutral-900 text-sm"
          >
            Load
          </button>
          <button
            onClick={save}
            class="px-3 py-1.5 rounded bg-neutral-800 text-white dark:bg-neutral-200 dark:text-neutral-900 text-sm"
          >
            Save
          </button>
          <button
            onClick={reload}
            class="px-3 py-1.5 rounded bg-sky-600 text-white hover:bg-sky-700 text-sm"
          >
            Save &amp; Reload
          </button>
          <button
            onClick={genHash}
            class="px-3 py-1.5 rounded bg-neutral-600 text-white hover:bg-neutral-700 text-sm"
          >
            Hash
          </button>
          <button
            onClick={shutdown}
            class="px-3 py-1.5 rounded bg-red-600 text-white hover:bg-red-700 text-sm"
          >
            Shutdown
          </button>
        </div>
      </div>
    </div>
  )
}
