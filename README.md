# Electronic Voting Platform (secure prototype)

INTE2667 Secure Software Systems, Assignment 3. A prototype of the AEC electronic voting
platform with the focus on security: enrolment and identity, candidate management, ballot
casting, and tally and results.

## Stack

- Backend: Python 3.13, Flask REST API, SQLAlchemy (SQLite in development, two separate
  databases: identity and ballots)
- Frontend: React (Vite)
- Tests: pytest

## Running it locally

Backend:
```
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python scripts/make_dev_cert.py
.venv/bin/python seed.py
.venv/bin/python run.py
```
The API runs on https://127.0.0.1:5000.

Frontend (second terminal):
```
cd frontend
npm install
npm run dev
```
Open https://localhost:5173. The dev certificate is self-signed, so the browser asks to
accept it the first time. The dev server forwards `/api` to the backend.

Demo accounts and their password are in `backend/seed.py` (development only).

## Layout

```
backend/
  app/
    auth/        login and role checks
    ballot/      eligibility, ballot tokens, encryption, casting
    tally/       chain verification and counting
    security/    CSRF, CORS, headers, TLS settings
    keys.py      key service (one key per purpose)
    models.py    identity and ballot database models
    audit.py     audit hook
  tests/         one test file per security requirement
frontend/
  src/           React app (api.js wraps all API calls)
```

Local-only folders (`backend/instance/` with keys, certificates and databases) are never
committed.

## Requirements

Security requirements SR-01 to SR-20 are tracked as GitHub issues. Each one has its own
test file in `backend/tests/` (for example `test_sr13_ballot_encryption.py`).

## Working on it

1. Branch from `main`: `git checkout -b <your-branch>`
2. Commit in small steps, with the requirement ID in the message (`SR-09: ...`)
3. Run `pytest` before pushing
4. Open a pull request into `main` and ask one teammate to review it
