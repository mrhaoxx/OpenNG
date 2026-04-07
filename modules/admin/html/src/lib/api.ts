import { csrfFetch } from './csrf'

export { csrfFetch }

export interface SpaceNode {
  name: string
  kind: string
  hasAdmin: boolean
}

export interface SpaceEdge {
  from: string
  to: string
}

export interface SpaceMapData {
  nodes: SpaceNode[]
  edges: SpaceEdge[]
}

export interface AdminMeta {
  root?: WidgetNode
}

export interface WidgetNode {
  type: string
  props: Record<string, unknown>
  children?: WidgetNode[]
}

export interface InstanceDetail {
  name: string
  kind: string
  dependsOn?: string[]
  dependedBy?: string[]
  admin?: AdminMeta
}

export function resolveSource(source: string, instanceName: string): string {
  if (source.startsWith('/')) return source
  return `/api/v1/instance/${instanceName}/${source}`
}

export async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export async function fetchSchema(): Promise<any> {
  return fetchJSON('/api/v1/cfg/schema')
}

export async function fetchConfigText(): Promise<string> {
  const res = await fetch('/api/v1/cfg/get')
  if (!res.ok) throw new Error(`${res.status}`)
  return res.text()
}
