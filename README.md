# QEase

QEase is an Express and SQLite queue-management app.

## Run locally

Install dependencies, then configure an administrator password before starting:

```powershell
npm install
$env:QEASE_ADMIN_PASSWORD = "replace-with-a-unique-password-of-at-least-12-characters"
npm start
```

The administrator username defaults to `admin`; override it with
`QEASE_ADMIN_USERNAME` if needed. To enable a staff account, set
`QEASE_STAFF_PASSWORD` (at least 12 characters); its username defaults to
`staff` and can be changed with `QEASE_STAFF_USERNAME`.

## Public ticket links

Set `QEASE_PUBLIC_BASE_URL` to the public URL used by customers' phones, for
example `https://queues.example.edu` or `http://192.168.1.20:3000` on a trusted
campus network. Generated ticket QR codes use this base URL. In production,
`QEASE_PUBLIC_BASE_URL` is required and must use HTTP or HTTPS unless the
hosting platform provides `RENDER_EXTERNAL_URL`.

For local development without this setting, ticket links use the address used
to open the dashboard. `QEASE_DB_PATH` can optionally point to a SQLite
database file; otherwise QEase uses `qease.db` in the project root.

## Public demo deployment on Render

1. Push this project to a GitHub repository you control.
2. In Render, create a **Blueprint** from that repository and apply the included
   `render.yaml`. Its build command compiles SQLite from source for compatibility
   with Render's runtime.
3. Wait for the deployment to finish, then open the generated
   `https://qease.onrender.com` service URL (Render may add a suffix if that
   name is unavailable). The app uses Render's `RENDER_EXTERNAL_URL` for QR
   tracking links, so scanned tickets point to the public service URL.
4. Open `/admin-login.html` on the service URL. The Blueprint generates a
   unique `QEASE_ADMIN_PASSWORD`; find it in the service's Environment settings
   in Render. The administrator username is `admin`.

The included Blueprint uses Render's **free** web-service plan and does not
attach a persistent disk. This is suitable for a public demo only: free
instances can sleep, and their local SQLite database can be erased during
restarts or redeploys. Use a paid plan with a persistent disk mounted at
`/var/data`, and set `QEASE_DB_PATH=/var/data/qease.db`, before storing
operational queue data. Never use the free ephemeral setup for important or
regulated records.

## Tests

Run the automated suite with:

```powershell
npm test
```

The tests use an isolated temporary SQLite database and do not change the
project's normal database.
