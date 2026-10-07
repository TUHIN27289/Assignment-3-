import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'

const EMPTY = { email: '', full_name: '', date_of_birth: '', address: '', division: '' }

// Enrolment officer: list electors and register citizens.
export default function Enrolment({ onSessionLost }) {
  const [voters, setVoters] = useState([])
  const [division, setDivision] = useState('')
  const [form, setForm] = useState(EMPTY)
  const [created, setCreated] = useState(null)
  const [error, setError] = useState('')

  const fail = useCallback((e) => (e.status === 401 ? onSessionLost() : setError(e.message)), [onSessionLost])
  const load = useCallback((div) => {
    const q = div ? `?division=${encodeURIComponent(div)}` : ''
    api(`/api/enrolment/voters${q}`).then((d) => setVoters(d.voters)).catch(fail)
  }, [fail])
  useEffect(() => { load('') }, [load])

  async function register(e) {
    e.preventDefault()
    setError('')
    setCreated(null)
    try {
      const r = await api('/api/enrolment/voters', { method: 'POST', body: form })
      setCreated(r)
      setForm(EMPTY)
      load(division)
    } catch (err) { fail(err) }
  }

  const field = (key, label, type = 'text') => (
    <label>{label}<input type={type} value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} required /></label>
  )

  return (
    <div className="card">
      <h1>Electoral roll</h1>
      <p className="muted">Personal details are stored encrypted. Every view of this list is recorded in the audit log.</p>
      {error && <p className="error" role="alert">{error}</p>}

      <form className="row" style={{ justifyContent: 'flex-start' }} onSubmit={(e) => { e.preventDefault(); load(division) }}>
        <input placeholder="Filter by division" value={division} onChange={(e) => setDivision(e.target.value)} aria-label="Division" />
        <button type="submit" className="secondary">Filter</button>
      </form>
      <table className="results">
        <tbody>
          {voters.map((v) => (
            <tr key={v.id}>
              <td><strong>{v.full_name}</strong><br /><span className="muted">{v.email}</span></td>
              <td className="muted">{v.date_of_birth}<br />{v.address}</td>
              <td>{v.division}<br /><span className="muted">{v.enrolled ? 'enrolled' : 'not enrolled'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>

      <form onSubmit={register} style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2>Register a citizen</h2>
        {field('full_name', 'Full name')}
        {field('email', 'Email', 'email')}
        {field('date_of_birth', 'Date of birth', 'date')}
        {field('address', 'Residential address')}
        {field('division', 'Division')}
        <div className="row"><button type="submit">Register</button></div>
      </form>
      {created && (
        <div className="alert">
          Registered {created.voter.full_name}. Temporary password (give it to the voter once, it won't be shown again):
          <code className="tracking">{created.temporary_password}</code>
        </div>
      )}
    </div>
  )
}
