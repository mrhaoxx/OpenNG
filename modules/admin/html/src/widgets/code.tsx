import { useState, useEffect } from 'preact/hooks'
import { resolveSource } from '../api'

interface CodeWidgetProps {
  source?: string
  content?: string
  language?: string
  instanceName: string
}

export function CodeWidget({ source, content: staticContent, language, instanceName }: CodeWidgetProps) {
  const [content, setContent] = useState<string>(staticContent || '')

  useEffect(() => {
    if (!source) return
    const url = resolveSource(source, instanceName)
    fetch(url)
      .then(r => r.text())
      .then(setContent)
      .catch(() => setContent('Error loading content'))
  }, [source, instanceName])

  return (
    <pre class={`p-3 rounded-lg bg-neutral-100 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 text-xs font-mono overflow-x-auto whitespace-pre-wrap text-neutral-800 dark:text-neutral-200 language-${language || 'text'}`}>
      {content}
    </pre>
  )
}
