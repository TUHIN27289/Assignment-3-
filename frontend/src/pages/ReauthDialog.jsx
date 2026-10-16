import { useState } from 'react'

// SR-06: asks for the password again before a sensitive change.
export default function ReauthDialog({ onDone }) {
  const [password, setPassword] = useState('')
  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
      <form className="card narrow" onSubmit={(e) => { e.preventDefault(); onDone(password) }}>
        <h1 id="reauth-title">Confirm it's you</h1>
        <p className="muted">This change needs your password again.</p>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password}
                 onChange={(e) => setPassword(e.target.value)} required autoFocus />
        </label>
        <div className="row">
          <button type="button" className="secondary" onClick={() => onDone(null)}>Cancel</button>
          <button type="submit">Confirm</button>
        </div>
      </form>
    </div>
  )
}
