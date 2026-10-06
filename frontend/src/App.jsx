import { useEffect, useState } from 'react'
import { getMe, logout } from './api'
import Login from './pages/Login'
import Receipt from './pages/Receipt'
import Tally from './pages/Tally'
import Vote from './pages/Vote'

const ROLE_LABELS = {
  voter: 'Voter',
  enrolment_officer: 'Enrolment officer',
  delegate: "Commissioner's delegate",
  tally_officer: 'Tally officer',
  auditor: 'Auditor',
}

export default function App() {
  const [user, setUser] = useState(undefined) // undefined = still checking
  const [receipt, setReceipt] = useState(null)

  useEffect(() => {
    getMe().then(setUser).catch(() => setUser(null))
  }, [])

  async function handleLogout() {
    await logout().catch(() => {})
    setUser(null)
  }

  // Server-side session expired or was cleared
  const onSessionLost = () => setUser(null)

  if (user === undefined) return <main className="page"><p>Loading…</p></main>

  return (
    <>
      <header className="topbar">
        <span className="brand">Electronic Voting Platform</span>
        {user && (
          <span className="who">
            {user.email} · {ROLE_LABELS[user.role] || user.role}
            <button className="link" onClick={handleLogout}>Sign out</button>
          </span>
        )}
      </header>
      <main className="page">
        {receipt && <Receipt trackingCode={receipt} onFinish={() => setReceipt(null)} />}
        {!user && !receipt && <Login onLogin={() => getMe().then(setUser)} />}
        {user?.role === 'voter' && (
          <Vote onSessionLost={onSessionLost} onCast={(code) => { setUser(null); setReceipt(code) }} />
        )}
        {user?.role === 'tally_officer' && <Tally onSessionLost={onSessionLost} />}
        {user && !['voter', 'tally_officer'].includes(user.role) && (
          <p>No screens for this role yet.</p>
        )}
      </main>
    </>
  )
}
