# Secure Electronic Voting Platform

## Project Overview
The Secure Electronic Voting Platform is a university web application designed to support secure electoral operations, voter roll verification, encrypted ballot casting, and tamper-evident audit logging. This repository hosts the application infrastructure, backend APIs, frontend interface, and automated test suite.

## Technology Stack
- **Backend:** Python 3.11, Flask
- **Frontend:** React 18, Vite
- **Database:** PostgreSQL 15
- **Containerization:** Docker, Docker Compose
- **Testing:** pytest
- **Continuous Integration:** GitHub Actions

## Current Project Status
This commit establishes the **shared project foundation**. It sets up the core Flask application factory, React landing page, PostgreSQL service configuration, Docker Compose setup, pytest suite, and GitHub Actions CI workflow.

**Note:** Specific security requirements (SR-01 to SR-20) are NOT yet implemented in this foundation. They are assigned to individual team members and will be implemented on dedicated feature branches.

## Project Structure
```
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   └── routes.py
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   └── test_health.py
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
├── .env.example
├── .gitignore
├── docker-compose.yml
├── README.md
└── requirements.md
```

## Local Development

### Prerequisites
- Python 3.11+
- Node.js 20+
- PostgreSQL (or Docker)

### Setup Steps
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Setup Backend:
   ```bash
   cd backend
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   pip install -r requirements.txt
   python run.py
   ```

3. Setup Frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## Docker Development
To run the full application stack (PostgreSQL, Flask Backend, React Frontend) via Docker Compose:

```bash
docker-compose up --build
```

Services:
- **Frontend:** http://localhost:3000
- **Backend Health Check:** http://localhost:5000/health
- **PostgreSQL Database:** localhost:5432

## Backend
The Flask backend uses the application factory pattern (`create_app`) located in `backend/app/__init__.py`. Configuration is loaded from environment variables defined in `backend/app/config.py`.

A minimal health check route is provided at:
- `GET /health` -> `{"status": "healthy", "service": "voting-backend"}`

## Frontend
The React frontend is built using Vite. The application source code is located in `frontend/src/`.

At this stage, the landing page displays:
`Secure Electronic Voting Platform`

## PostgreSQL
PostgreSQL is configured to run inside a Docker container (`voting_db`) using environment variables defined in `.env`.

Connection settings:
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_DB`
- `DATABASE_URL`

## Testing
Backend tests are implemented using `pytest`.

To run the backend tests:
```bash
cd backend
pytest
```

## CI
Continuous Integration is configured using GitHub Actions (`.github/workflows/ci.yml`). The workflow triggers on pushes and pull requests to `main` and `dev` branches to:
1. Install backend dependencies and run `pytest`.
2. Install frontend dependencies and verify `npm run build`.

## Development Workflow
1. Development is performed on feature branches created off the `dev` branch.
2. Changes must pass local pytest and frontend build checks before submitting pull requests to `dev`.
3. Pull requests are merged into `dev` after review and passing CI builds.

## Security Requirements
Security requirements are defined in `requirements.md`:
- **SR-01 to SR-04:** Identity, Access & Audit (Assigned to Toukir)
- **SR-09 to SR-12:** Voter Registration & Roll Management (Assigned to Sehara)
- **SR-13 to SR-16:** Encryption, Unlinkability & Integrity Chain (Assigned to Mykhailo)

## Current Limitations
- Security requirements SR-01 through SR-20 are not implemented in this shared foundation.
- Authentication, authorization (RBAC), and user login flows are not implemented.
- Voting interface, ballot casting, ballot encryption, and tallying are not implemented.
- Database tables for voters, ballots, and audit logs are not yet created.
