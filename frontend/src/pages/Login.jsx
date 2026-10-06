import { useState } from 'react'
import { login } from '../api'

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(email, password)
      onLogin()
    } catch {
      // Same message for every failure, so it doesn't reveal which part was wrong
      setError('Sign in failed. Check your details and try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card narrow" onSubmit={submit}>
      <h1>Sign in</h1>
      <label>
        Email
        <input type="email" autoComplete="username" value={email}
               onChange={(e) => setEmail(e.target.value)} required />
      </label>
      <label>
        Password
        <input type="password" autoComplete="current-password" value={password}
               onChange={(e) => setPassword(e.target.value)} required />
      </label>
      {error && <p className="error" role="alert">{error}</p>}
      <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  )
}
