// Small wrapper around fetch for the Flask API.
//
// Security notes (SR-16):
// - The session lives in an HttpOnly cookie that JavaScript can't read.
//   Nothing sensitive goes into localStorage or sessionStorage.
// - The CSRF token is kept in memory only and sent in the X-CSRF-Token
//   header on every request that changes something.

let csrfToken = null
let reauthHandler = null

// SR-06: the app registers a function that asks the user for their password
// when the server says a sensitive action needs recent re-authentication.
export function onReauthNeeded(fn) {
  reauthHandler = fn
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

async function refreshCsrf() {
  const r = await fetch('/api/auth/csrf', { credentials: 'same-origin' })
  csrfToken = (await r.json()).csrf_token
}

export async function api(path, { method = 'GET', body } = {}, retried = false) {
  const unsafe = method !== 'GET'
  if (unsafe && !csrfToken) await refreshCsrf()
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (unsafe) headers['X-CSRF-Token'] = csrfToken

  const r = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = await r.json().catch(() => ({}))
  if (r.status === 401 && data.message === 'reauth_required' && reauthHandler && !retried) {
    const password = await reauthHandler()
    if (password) {
      await api('/api/auth/reauth', { method: 'POST', body: { password } }, true)
      return api(path, { method, body }, true)
    }
  }
  if (!r.ok) throw new ApiError(r.status, data.message || data.error || 'Request failed')
  return data
}

export async function login(email, password) {
  await refreshCsrf()
  const data = await api('/api/auth/login', { method: 'POST', body: { email, password } })
  csrfToken = data.csrf_token // server issues a new session on login
  return data
}

export async function logout() {
  await api('/api/auth/logout', { method: 'POST' })
  csrfToken = null
}

export const getMe = () => api('/api/auth/me')
