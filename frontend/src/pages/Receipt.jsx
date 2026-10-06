export default function Receipt({ trackingCode, onFinish }) {
  return (
    <div className="card">
      <h1>Your vote has been cast</h1>
      <p>Your tracking code:</p>
      <code className="tracking">{trackingCode}</code>
      <p className="muted">
        Keep this code to check your ballot was included. It does not show who you voted for.
        You have been signed out, and the ballot was sent without your identity attached.
      </p>
      <button onClick={onFinish}>Finish</button>
    </div>
  )
}
