# Secure Electronic Voting Platform

## Overview
The **Secure Electronic Voting Platform** is a web application designed to support secure electoral operations, voter roll verification, atomic ballot casting, signed voter receipt generation, and server-side security controls.

This repository hosts the Flask backend API, React/Vite frontend client, PostgreSQL database containerization, automated pytest suite, and GitHub Actions CI workflow.

---

## Features & Implemented Requirements

### SR-09 — One Vote Per Voter
- **Database Schema:** `voters` table tracks `voter_identifier`, `is_eligible` (boolean eligibility flag), `has_voted` (boolean vote status flag), and `voted_at` (timestamp of successful vote).
- **Atomic Single-Vote Enforcement:** Implemented in `Voter.cast_vote_once()` using PostgreSQL row-level atomic conditional updates:
  ```sql
  UPDATE voters
  SET has_voted = TRUE,
      voted_at = NOW()
  WHERE voter_identifier = %s
    AND is_eligible = TRUE
    AND has_voted = FALSE
  RETURNING voter_identifier, is_eligible, has_voted, voted_at;
  ```
- **Race Condition Safety:** Eliminates SELECT-before-UPDATE race conditions under high concurrency. Simultaneous duplicate voting attempts permit exactly one successful vote and reject subsequent attempts with HTTP 409 (`ALREADY_VOTED`).

### SR-10 — Signed Voter Receipt & Tracking Code
- **Cryptographic Receipts:** Generates an HMAC-SHA256 digital signature and a unique 32-character hexadecimal tracking code (`ReceiptService`) upon every successful vote.
- **Zero-Choice Privacy Guarantee:** Receipts include only the tracking code, voter identifier, timestamp, and signature. Candidate selections and ballot preferences are **never** stored or encoded in receipts.
- **Single-Transaction Boundary:** The voter status update (`has_voted = TRUE`) and receipt persistence (`receipts` table) execute within a single atomic database transaction. Any failure during processing triggers an immediate `conn.rollback()`.

### SR-11 — Server-Side Input & Ballot Validation
- **Pre-Database Validation Engine:** `BallotValidator` validates request structure and candidate preference rankings before any database locks or vote transactions are initiated.
- **Business Rule Enforcement:**
  - Rejects duplicate candidate IDs (`DUPLICATE_CANDIDATE`).
  - Rejects duplicate rank values (`DUPLICATE_RANK`).
  - Enforces ranking starting at rank `1` (`INVALID_RANK_START`).
  - Enforces a strictly contiguous $1..N$ ranking sequence without gaps (`DISCONTINUOUS_RANKS`).
- **SQL Injection Prevention:** All SQL queries use parameterized placeholders (`%s` for PostgreSQL, `?` for SQLite). User inputs are never concatenated into raw SQL statements.

### SR-12 — Diplomatic Mission IP Range Restriction
- **Server-Observed IP Extraction:** Uses `request.remote_addr` determined by the WSGI server (`DiplomaticIPValidator`). Arbitrary client HTTP headers (`X-Forwarded-For`, `X-Real-IP`) are not trusted by default to prevent IP spoofing attacks.
- **CIDR Subnet Validation:** Validates client IP against configured network subnets (`DIPLOMATIC_MISSION_IP_RANGES`) with full IPv4 and IPv6 support.
- **Deny-by-Default:** Missing or unconfigured CIDR ranges deny access by default (HTTP 403 `IP_NOT_ALLOWED`) with zero database side-effects.

---

## Technology Stack
- **Backend:** Python 3.12, Flask
- **Frontend:** React 18, Vite
- **Database:** PostgreSQL 15 (Production / Docker), SQLite (Local unit testing)
- **Containerization:** Docker, Docker Compose
- **Testing:** pytest
- **Continuous Integration:** GitHub Actions (`.github/workflows/ci.yml`)

---

## Project Structure
```text
.
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI workflow
├── backend/
│   ├── app/
│   │   ├── __init__.py        # Flask app factory & automatic DB init
│   │   ├── config.py          # Application & Testing configuration
│   │   ├── db.py              # PostgreSQL & SQLite connection / DDL schema
│   │   ├── ip_validator.py    # DiplomaticIPValidator service (SR-12)
│   │   ├── models.py          # Voter DAO & atomic cast_vote_once (SR-09)
│   │   ├── receipts.py        # ReceiptService & HMAC-SHA256 signatures (SR-10)
│   │   ├── routes.py          # API route definitions (/api/v1/votes/cast)
│   │   └── validators.py      # BallotValidator preference rules (SR-11)
│   ├── tests/
│   │   ├── conftest.py        # Pytest fixtures & test app setup
│   │   ├── test_ballot_validator.py
│   │   ├── test_health.py
│   │   ├── test_ip_validator.py
│   │   ├── test_receipt_foundation.py
│   │   ├── test_voter_one_vote.py
│   │   ├── test_voter_schema.py
│   │   └── test_voting_routes.py
│   ├── Dockerfile
│   ├── pytest.ini
│   ├── requirements.txt
│   └── run.py
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── Dockerfile
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── .env.example               # Template environment configuration
├── .gitignore                 # Git ignore rules (.env isolation)
├── docker-compose.yml         # Container orchestration manifest
├── README.md                  # System & setup documentation
└── requirements.md            # Security requirements specification
```

---

## Environment Configuration

Configuration is managed via environment variables defined in `.env` (copied from `.env.example`).

| Variable Name | Description / Purpose | Default / Example Value | Secrets & Production Notes |
|---|---|---|---|
| `FLASK_APP` | Entry point script for Flask server | `run.py` | Framework configuration |
| `FLASK_ENV` | Application environment mode | `development` | Set to `production` in live deployment |
| `SECRET_KEY` | Flask application session secret | `dev-secret-key-change-in-production` | **MUST CHANGE** in production |
| `RECEIPT_SECRET_KEY` | HMAC key for signing receipts | `dev-receipt-secret-change-in-production` | **MUST CHANGE** in production |
| `BACKEND_PORT` | Host port mapped to Flask backend | `5000` | Port allocation |
| `POSTGRES_USER` | Database superuser account | `voting_user` | Configure securely |
| `POSTGRES_PASSWORD` | Database user password | `voting_password` | **MUST CHANGE** in production |
| `POSTGRES_DB` | Production PostgreSQL database name | `voting_db` | Database name |
| `POSTGRES_HOST` | Hostname of PostgreSQL service | `db` (Docker) / `localhost` | Container or host hostname |
| `POSTGRES_PORT` | PostgreSQL server port | `5432` | Database port |
| `DATABASE_URL` | Complete DB connection string | `postgresql://voting_user:voting_password@db:5432/voting_db` | Derived or explicit connection URI |
| `DIPLOMATIC_MISSION_IP_RANGES` | Comma-separated allowed CIDRs | `192.0.2.0/24,2001:db8::/32` (Example) | **MUST CONFIGURE** approved CIDRs in production |
| `VITE_API_BASE_URL` | API endpoint URI for Vite proxy | `http://localhost:5000` | Frontend backend endpoint target |
| `FRONTEND_PORT` | Host port mapped to React frontend | `3000` | Port allocation |

---

## First-Time Setup & Installation

### Prerequisites
- **Docker & Docker Compose** (Recommended), OR
- **Python 3.11+**, **Node.js 20+**, and **PostgreSQL 15+**

### Step-by-Step Setup

1. **Clone the Repository:**
   ```bash
   git clone <repository-url>
   cd Assignment-3-
   ```

2. **Configure Environment Variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to configure desired ports, secret keys, and diplomatic mission CIDR ranges.

3. **Option A: Run Stack via Docker Compose (Recommended)**
   ```bash
   docker compose up --build -d
   ```
   - **React Frontend:** `http://localhost:3000`
   - **Backend API Health Check:** `http://localhost:5000/health`
   - **PostgreSQL Database:** `localhost:5432`

4. **Option B: Manual Local Setup (Without Docker)**

   **Backend Setup:**
   ```bash
   cd backend
   python -m venv venv
   # On Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate

   pip install -r requirements.txt
   python run.py
   ```

   **Frontend Setup:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## Docker Deployment & Automatic Database Initialization

When launched via Docker Compose, the system manages services automatically:
- **`voting_db` Container:** Launches PostgreSQL 15 and initializes the `voting_db` database.
- **`voting_backend` Container:** Waits for PostgreSQL to become healthy, connects, and automatically runs `init_db()`.
- **Automatic Table Initialization:** `init_db()` executes idempotent DDL statements (`CREATE TABLE IF NOT EXISTS`):
  - `voters` table (with lookup index `idx_voters_lookup`)
  - `receipts` table (with lookup index `idx_receipts_voter_identifier`)
- **No Manual SQL Execution Required:** Database tables are created automatically on startup.

---

## API Documentation

### Cast Vote Endpoint

`POST /api/v1/votes/cast`

Processes voter authorization, ballot input validation, single-vote enforcement, and digital receipt generation.

#### Request Headers
- `Content-Type: application/json`

#### Request Payload Example
```json
{
  "voter_identifier": "VOTER-98765",
  "election_id": "AEC-ELECTION-2026",
  "preferences": [
    { "candidate_id": "CAND-1", "rank": 1 },
    { "candidate_id": "CAND-2", "rank": 2 },
    { "candidate_id": "CAND-3", "rank": 3 }
  ]
}
```

#### Success Response (HTTP 200 OK)
```json
{
  "success": true,
  "status": "SUCCESS",
  "message": "Vote recorded successfully.",
  "receipt": {
    "tracking_code": "c4ca4238a0b923820dcc509a6f75849b",
    "voter_identifier": "VOTER-98765",
    "voted_at": "2026-10-06T11:00:00.000000",
    "signature": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
  }
}
```

#### Status & Error Code Summary

| HTTP Status | Status Code | Reason / Description |
|---|---|---|
| `200 OK` | `SUCCESS` | Vote recorded atomically and signed receipt issued. |
| `400 Bad Request` | `INVALID_IDENTIFIER` | Request missing valid `voter_identifier`. |
| `400 Bad Request` | `INVALID_BALLOT` | Preference rankings failed validation (duplicates, gaps, invalid starting rank). |
| `403 Forbidden` | `IP_NOT_ALLOWED` | Client IP address is outside configured diplomatic mission CIDR ranges. |
| `403 Forbidden` | `INELIGIBLE` | Voter is marked ineligible (`is_eligible = FALSE`). |
| `409 Conflict` | `ALREADY_VOTED` | Voter has already cast a vote (`has_voted = TRUE`). |
| `500 Server Error` | `SERVER_ERROR` | Internal server error; database transaction rolled back. |

---

## Testing

Backend unit and integration tests are powered by `pytest`.

### Running Tests Locally

Run the complete test suite against default SQLite in-memory database:
```bash
python -m pytest -q
```

Run tests against a running PostgreSQL container:
```bash
$env:TEST_POSTGRES_URL="postgresql://voting_user:voting_password@localhost:5433/voting_db"
python -m pytest -q
```

Run formatting checks:
```bash
git diff --check
```

---

## Production Security Notes

1. **Secret Key Management:** Change `SECRET_KEY` and `RECEIPT_SECRET_KEY` in `.env` before production deployment.
2. **Database Credentials:** Change `POSTGRES_PASSWORD` to a strong random passphrase in production environments.
3. **Environment File Isolation:** Never commit `.env` files to version control (`.gitignore` enforces this rule).
4. **Diplomatic Network CIDRs:** Configure `DIPLOMATIC_MISSION_IP_RANGES` with official CIDR blocks approved by electoral authorities. Do not leave empty or use documentation test blocks (`192.0.2.0/24`) in production.
5. **Reverse Proxy & Trusted Proxies:** If deploying behind a reverse proxy (e.g. NGINX, AWS ALB), ensure trusted proxy headers are properly terminated so `request.remote_addr` accurately reflects client IP.

---

## Troubleshooting

- **Database Connection Refused:** Ensure PostgreSQL container is running (`docker compose ps`) and ports match `DATABASE_URL` settings.
- **IP Denied (403 IP_NOT_ALLOWED):** Ensure your client IP or `127.0.0.1/32` is included in `DIPLOMATIC_MISSION_IP_RANGES` during local development.
- **PostgreSQL Concurrency Test Skipped:** When running pytest without `TEST_POSTGRES_URL`, the PostgreSQL race-condition test will be safely skipped. Pass `TEST_POSTGRES_URL` to enable it.
