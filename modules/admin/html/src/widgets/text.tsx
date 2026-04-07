interface TextWidgetProps {
  content?: string
  html?: string
  class?: string
}

export function TextWidget({ content, html, class: className }: TextWidgetProps) {
  if (html) {
    return <div class={`text-sm text-neutral-700 dark:text-neutral-300 ${className || ''}`} dangerouslySetInnerHTML={{ __html: html }} />
  }
  return <div class={`text-sm text-neutral-700 dark:text-neutral-300 ${className || ''}`}>{content}</div>
}
