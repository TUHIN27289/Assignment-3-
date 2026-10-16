import { useEffect, useState } from 'react'
import { api } from '../api'

// Voter's own enrolment: status check and address update.
export default function MyEnrolment({ onSessionLost }) {
  const [me, setMe] = useState(null)
  const [address, setAddress] = useState('')
  const [editing, setEditing] = useState(false)
  const [msg, setMsg] = useState('')

  const fail = (e) => (e.status === 401 ? onSessionLost() : setMsg(e.message))

  useEffect(() => {
    api('/api/enrolment/me').then(setMe).catch((e) => (e.status === 401 ? onSessionLost() : setMsg(e.message)))
  }, [onSessionLost])

  async function save(e) {
    e.preventDefault()
    setMsg('')
    try {
      setMe(await api('/api/enrolment/me/address', { method: 'PUT', body: { address } }))
      setEditing(false)
      setMsg('Address updated.')
    } catch (err) { fail(err) }
  }

  if (!me) return null
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>My enrolment</h2>
      <p>
        {me.full_name} · Division of {me.division} ·{' '}
        <strong>{me.enrolled ? 'Enrolled' : 'Not enrolled'}</strong>
      </p>
      {!editing ? (
        <p className="muted">
          Address: {me.address || 'not recorded'}{' '}
          <button className="link" onClick={() => { setAddress(me.address || ''); setEditing(true) }}>Update</button>
        </p>
      ) : (
        <form onSubmit={save} className="row" style={{ justifyContent: 'flex-start' }}>
          <input style={{ flex: 1 }} value={address} onChange={(e) => setAddress(e.target.value)}
                 aria-label="New address" minLength={5} maxLength={200} required />
          <button type="button" className="secondary" onClick={() => setEditing(false)}>Cancel</button>
          <button type="submit">Save</button>
        </form>
      )}
      {msg && <p className="muted">{msg}</p>}
    </div>
  )
}
