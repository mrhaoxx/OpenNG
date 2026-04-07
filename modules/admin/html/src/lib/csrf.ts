const CSRF_COOKIE_NAME = 'ngcsrf'
const CSRF_HEADER_NAME = 'X-CSRF-Token'

function readCookie(name: string): string | undefined {
  const pairs = document.cookie ? document.cookie.split('; ') : []
  for (const pair of pairs) {
    if (!pair) continue
    const index = pair.indexOf('=')
    if (index === -1) continue
    const key = pair.slice(0, index)
    if (key === name) {
      return decodeURIComponent(pair.slice(index + 1))
    }
  }
  return undefined
}

export function getCsrfToken(): string | undefined {
  return readCookie(CSRF_COOKIE_NAME)
}

export function withCsrf(init: RequestInit = {}): RequestInit {
  const token = getCsrfToken()
  const headers = new Headers(init.headers ?? undefined)
  if (token) {
    headers.set(CSRF_HEADER_NAME, token)
  }
  return {
    ...init,
    headers,
    credentials: init.credentials ?? 'same-origin'
  }
}

export function csrfFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return fetch(input, withCsrf(init))
}

export { CSRF_HEADER_NAME, CSRF_COOKIE_NAME }
