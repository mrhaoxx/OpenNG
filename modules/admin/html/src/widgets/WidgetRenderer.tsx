import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { WidgetNode } from '@/lib/api'
import TableWidget from './TableWidget'
import ActionWidget from './ActionWidget'
import StatWidget from './StatWidget'

interface Props {
  widget: WidgetNode
  instanceName: string
}

export default function WidgetRenderer({ widget, instanceName }: Props) {
  const { type, props = {}, children = [] } = widget

  switch (type) {
    case 'columns':
      return (
        <div className="grid grid-cols-12 gap-4">
          {children.map((c, i) => <WidgetRenderer key={i} widget={c} instanceName={instanceName} />)}
        </div>
      )
    case 'column':
      return (
        <div style={{ gridColumn: `span ${(props.span as number) || 12}` }}>
          {children.map((c, i) => <WidgetRenderer key={i} widget={c} instanceName={instanceName} />)}
        </div>
      )
    case 'card':
      return (
        <Card className="mb-4">
          {props.title != null && (
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">{String(props.title)}</CardTitle>
            </CardHeader>
          )}
          <CardContent className={props.title != null ? 'pt-0' : ''}>
            {children.map((c, i) => <WidgetRenderer key={i} widget={c} instanceName={instanceName} />)}
          </CardContent>
        </Card>
      )
    case 'row':
      return (
        <div className="flex gap-4">
          {children.map((c, i) => <WidgetRenderer key={i} widget={c} instanceName={instanceName} />)}
        </div>
      )
    case 'table':
      return <TableWidget {...props} instanceName={instanceName} />
    case 'action':
      return <ActionWidget {...props} instanceName={instanceName} />
    case 'stat':
      return <StatWidget {...props} instanceName={instanceName} />
    case 'text':
      return <p className="text-sm text-muted-foreground mb-2">{String(props.content ?? '')}</p>
    default:
      return (
        <div className="border border-dashed border-yellow-600 rounded-lg p-3 mb-4 text-xs text-yellow-500">
          Unknown widget: <code>{type}</code>
          <pre className="mt-2 text-[10px] opacity-70 overflow-auto">{JSON.stringify(props, null, 2)}</pre>
        </div>
      )
  }
}
