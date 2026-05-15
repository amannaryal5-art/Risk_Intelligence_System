# RiskIntel v3.0 UI

RiskIntel v3.0 is a FastAPI + Jinja2 + vanilla JavaScript command-center UI for autonomous threat intelligence operations. It ships without a Node.js build step and mounts the existing backend in-process so all UI calls stay on relative `/api/v1/...` routes.

## Stack

- FastAPI serves both the UI shell and the existing API backend
- Jinja2 templates for route-level pages
- Vanilla ES modules for the runtime
- WebSocket + EventSource live transport
- Precompiled CSS utility/component layer aligned to the RiskIntel design tokens

## Launch

```bash
cd C:\git\Risk_Intelligence_System
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Open `http://localhost:8000`

## Architecture

- `app.py`: UI entrypoint, security headers, Jinja routes, static mount, backend mount
- `templates/`: shared shell plus route templates for command, cases, feeds, campaigns, actors, assets, reports, workbench, settings, login
- `static/js/app.js`: bootstraps auth, routing, command palette, shortcuts, live stream, top shell behavior
- `static/js/liveBus.js`: pure WebSocket + SSE manager with heartbeat, backoff, queueing
- `static/js/*.js`: per-view controllers that fetch live endpoints only and degrade gracefully when an endpoint is absent
- `static/css/app.css`: production-ready command center styling, tokens, responsive behavior, reduced-motion support

## Endpoint Strategy

The UI calls the live backend routes directly and does not ship any mock data. If an expected endpoint is not yet implemented by the backend, the page shows a structured degraded-state panel instead of inventing placeholder results.

Examples:

- Command Center: `/api/v1/dashboard/stats`, `/api/v1/dashboard/activity`, `/api/v1/scans/active`
- Cases: `/api/v1/cases`, `/api/v1/cases/{id}`, fallback support for generic `PATCH /api/v1/cases/{id}`
- Feeds: `/api/v1/feeds/status`, `/api/v1/feeds/status/live`, `/api/v1/feeds/quota`, `/api/v1/feeds/{id}/probe`
- Intelligence: `/api/v1/ioc/{type}/{value}`, `/api/v1/ioc/stream`, `/ws/live`

## Security

- CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
- No `localStorage` token persistence
- Relative API calls for reverse-proxy compatibility
- Escaped user-controlled output before rendering

## Browser Compatibility

- Chrome / Edge current
- Firefox current
- Safari 17+

## Notes

- The current backend in this repository exposes only part of the target RiskIntel v3.0 API surface. The UI is already wired to the full contract and will automatically light up additional screens as those endpoints come online.
- The legacy Next.js code remains in the repository, but the new launch path is `python app.py`.
