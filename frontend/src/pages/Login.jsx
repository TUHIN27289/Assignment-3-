import { useState } from 'react'
import { login, mfaSetup, mfaVerify } from '../api'

// Steps: password -> (staff only) MFA setup on first login, or MFA code.
export default function Login({ onLogin }) {
  const [step, setStep] = useState('password') // password | setup | code
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [setup, setSetup] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function run(fn) {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch {
      // Same message for every failure, so it doesn't reveal which part was wrong
      setError(step === 'password'
        ? 'Sign in failed. Check your details and try again.'
        : 'That code did not work. Wait for a new code and try again.')
      if (step !== 'password') setCode('')
    } finally {
      setBusy(false)
    }
  }

  const submitPassword = (e) => {
    e.preventDefault()
    run(async () => {
      const data = await login(email, password)
      setPassword('')
      if (data.mfa_setup_required) {
        setSetup(await mfaSetup())
        setStep('setup')
      } else if (data.mfa_required) {
        setStep('code')
      } else {
        onLogin()
      }
    })
  }

  const submitCode = (e) => {
    e.preventDefault()
    run(async () => {
      await mfaVerify(code)
      onLogin()
    })
  }

  if (step === 'password') {
    return (
      <form className="card narrow" onSubmit={submitPassword}>
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

  return (
    <form className="card narrow" onSubmit={submitCode}>
      {step === 'setup' ? (
        <>
          <h1>Set up two-step sign-in</h1>
          <p className="muted">
            Staff accounts need an authenticator app (for example Microsoft or Google Authenticator).
            Add a new account in the app using this key, then enter the 6-digit code it shows.
          </p>
          <code className="tracking">{setup.secret.match(/.{1,4}/g).join(' ')}</code>
          <a className="muted" href={setup.otpauth_uri}>Open in authenticator app</a>
        </>
      ) : (
        <>
          <h1>Enter your code</h1>
          <p className="muted">Open your authenticator app and enter the current 6-digit code.</p>
        </>
      )}
      <label>
        Code
        <input inputMode="numeric" autoComplete="one-time-code" maxLength={6} pattern="\d{6}" value={code}
               onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} required autoFocus />
      </label>
      {error && <p className="error" role="alert">{error}</p>}
      <button type="submit" disabled={busy || code.length !== 6}>{busy ? 'Checking…' : 'Continue'}</button>
    </form>
  )
}
