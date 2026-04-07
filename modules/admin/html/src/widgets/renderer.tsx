import type { Widget } from './types'
import { TableWidget } from './table'
import { StatWidget } from './stat'
import { ActionWidget } from './action'
import { TextWidget } from './text'
import { StreamWidget } from './stream'
import { KVWidget } from './kv'
import { CodeWidget } from './code'
import { FormWidget } from './form'

type Renderer = (props: any, children: Widget[], instanceName: string) => any

const registry: Record<string, Renderer> = {
  // Layout
  columns: (props, children, name) => (
    <div class="grid grid-cols-12 gap-4">
      {children.map((c, i) => <span key={i}>{renderWidget(c, name)}</span>)}
    </div>
  ),
  column: (props, children, name) => (
    <div style={{ gridColumn: `span ${props.span || 12}` }}>
      {children.map((c, i) => <span key={i}>{renderWidget(c, name)}</span>)}
    </div>
  ),
  card: (props, children, name) => (
    <div class="border border-neutral-200 dark:border-neutral-800 rounded-lg p-4 mb-4">
      {props.title && <h3 class="text-base font-semibold mb-3 text-neutral-900 dark:text-neutral-100">{props.title}</h3>}
      {children.map((c, i) => <span key={i}>{renderWidget(c, name)}</span>)}
    </div>
  ),
  row: (props, children, name) => (
    <div class="flex gap-4 flex-wrap">
      {children.map((c, i) => <span key={i}>{renderWidget(c, name)}</span>)}
    </div>
  ),
  section: (props, children, name) => (
    <div class="mb-6">
      {props.title && <h2 class="text-sm font-semibold uppercase tracking-wider text-neutral-500 mb-3">{props.title}</h2>}
      {children.map((c, i) => <span key={i}>{renderWidget(c, name)}</span>)}
    </div>
  ),

  // Data
  table: (props, _children, name) => <TableWidget {...props} instanceName={name} />,
  stat: (props, _children, name) => <StatWidget {...props} instanceName={name} />,
  text: (props) => <TextWidget {...props} />,
  stream: (props, _children, name) => <StreamWidget {...props} instanceName={name} />,
  kv: (props, _children, name) => <KVWidget {...props} instanceName={name} />,
  code: (props, _children, name) => <CodeWidget {...props} instanceName={name} />,
  form: (props, _children, name) => <FormWidget {...props} instanceName={name} />,

  // Interactive
  action: (props, _children, name) => <ActionWidget {...props} instanceName={name} />,
}

export function renderWidget(widget: Widget, instanceName: string): any {
  if (!widget || !widget.type) return null
  const renderer = registry[widget.type]
  if (!renderer) {
    return (
      <div class="border border-dashed border-yellow-500 rounded p-2 text-xs text-yellow-600 mb-2">
        Unknown widget: {widget.type}
        <pre class="mt-1 text-xs overflow-auto">{JSON.stringify(widget.props, null, 2)}</pre>
      </div>
    )
  }
  return renderer(widget.props || {}, widget.children || [], instanceName)
}
