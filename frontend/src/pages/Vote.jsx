import { useEffect, useState } from 'react'
import { api, logout } from '../api'

// Voting flow, matching the backend's split between identity and ballot (SR-14):
//   1. signed in: load candidates, fill in and review the ballot
//   2. on confirm: get a one-time ballot token while still signed in
//   3. sign out, so the session is gone
//   4. cast the ballot with only the token, as an anonymous request
export default function Vote({ onSessionLost, onCast }) {
  const [info, setInfo] = useState(null)
  const [prefs, setPrefs] = useState({})
  const [step, setStep] = useState('fill') // fill | review | sending
  const [error, setError] = useState('')

  useEffect(() => {
    api('/api/ballot/candidates')
      .then(setInfo)
      .catch((e) => (e.status === 401 ? onSessionLost() : setError(e.message)))
  }, [onSessionLost])

  if (error && !info) return <p className="error">{error}</p>
  if (!info) return <p>Loading ballot…</p>

  if (info.issued) {
    return <div className="card"><h1>Already voted</h1><p>A ballot has already been issued for your enrolment.</p></div>
  }

  const n = info.candidates.length
  const numbers = Object.values(prefs).filter(Boolean).map(Number)
  const complete = numbers.length === n && new Set(numbers).size === n
    && numbers.every((x) => x >= 1 && x <= n)
  const ordered = [...info.candidates].sort((a, b) => prefs[a.id] - prefs[b.id])

  async function confirm() {
    setStep('sending')
    setError('')
    try {
      const { ballot_token: token } = await api('/api/ballot/token', { method: 'POST' })
      await logout()
      const { tracking_code } = await api('/api/ballot/cast', {
        method: 'POST',
        body: { ballot_token: token, ballot: { house: ordered.map((c) => c.id) } },
      })
      onCast(tracking_code)
    } catch (e) {
      setError(e.message)
      setStep('review')
    }
  }

  if (step === 'review' || step === 'sending') {
    return (
      <div className="card">
        <h1>Check your ballot</h1>
        <p>House of Representatives, {info.division}</p>
        <ol className="review">
          {ordered.map((c) => <li key={c.id}>{c.name} <span className="muted">({c.party})</span></li>)}
        </ol>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="row">
          <button className="secondary" onClick={() => setStep('fill')} disabled={step === 'sending'}>Change</button>
          <button onClick={confirm} disabled={step === 'sending'}>
            {step === 'sending' ? 'Casting…' : 'Confirm and cast vote'}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <h1>House of Representatives</h1>
      <p>Division of {info.division}. Number every box from 1 to {n} in the order of your choice.</p>
      <table className="ballot">
        <tbody>
          {info.candidates.map((c) => (
            <tr key={c.id}>
              <td>
                <input className="box" inputMode="numeric" maxLength={2} aria-label={`Preference for ${c.name}`}
                       value={prefs[c.id] || ''}
                       onChange={(e) => setPrefs({ ...prefs, [c.id]: e.target.value.replace(/\D/g, '') })} />
              </td>
              <td><strong>{c.name}</strong><br /><span className="muted">{c.party}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {!complete && numbers.length > 0 && (
        <p className="muted">Each number from 1 to {n} must be used exactly once.</p>
      )}
      <button disabled={!complete} onClick={() => setStep('review')}>Review ballot</button>
    </div>
  )
}
