export function resolveSource(source: string, instanceName: string): string {
  if (source.startsWith('/')) return source
  return `/api/v1/instance/${instanceName}/${source}`
}

export { csrfFetch, getCsrfToken, withCsrf } from './csrf'
