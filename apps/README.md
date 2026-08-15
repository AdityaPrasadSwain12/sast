# SAST Scan Web Apps

This folder contains the web integration layer for the scanner.

```text
apps/backend   Django API wrapper around the existing scanner core
apps/frontend  React dashboard UI for starting scans and reviewing reports
```

The scanner engine still lives in `src/sast_scan`. The web apps call that scanner; they do not duplicate OpenGrep or Trivy logic.

## Backend

Install and prepare:

```powershell
python -m pip install -r apps\backend\requirements.txt
python apps\backend\manage.py migrate
python apps\backend\manage.py runserver 127.0.0.1:8000
```

API endpoints:

```text
GET  /api/health/
GET  /api/scans/
POST /api/scans/
GET  /api/scans/<job_id>/
GET  /api/scans/<job_id>/report/json/
GET  /api/scans/<job_id>/report/html/
GET  /api/scans/<job_id>/report/sarif/
GET  /api/scans/<job_id>/report/pdf/
GET  /api/reports/latest/
GET  /api/reports/latest/json/
GET  /api/reports/latest/html/
GET  /api/reports/latest/sarif/
GET  /api/reports/latest/pdf/
```

Supported scan inputs:

```text
github      public GitHub URL
file        uploaded single file
folder      uploaded folder/files
local_path  local path inside the scanner workspace
```

The web workflow uses the scanner's canonical report folder. Every new scan overwrites the latest report files:

```text
reports\scan.json
reports\scan.html
reports\scan.sarif
reports\scan.pdf
```

The Django database stores only lightweight job state for the UI, such as status, timestamps, target, and summary. The vulnerability data shown in the dashboard comes from the generated scanner report.

## Frontend

Install and run:

```powershell
cd apps\frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The Vite dev server proxies `/api` requests to:

```text
http://127.0.0.1:8000
```

Production build:

```powershell
npm run build
```

## Architecture

```text
React UI
  -> Django API
      -> sast_scan ScanOrchestrator
          -> OpenGrep Docker
          -> Trivy Docker
      -> JSON / HTML / SARIF / PDF reports
  -> UI polls scan status and displays findings
```
