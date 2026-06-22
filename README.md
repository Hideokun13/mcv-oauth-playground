# MyCourseVille OAuth Playground

A small local Node.js app for testing the MyCourseVille OAuth authorization-code
flow and the public `GET /api/v1/public/users/me` endpoint.

The dashboard UI is adapted from the earlier Gemini playground, while the
backend keeps OAuth tokens server-side and validates the OAuth `state`.

## Before running

The redirect URI registered with MyCourseVille must exactly match the
`MCV_REDIRECT_URI` value in `.env`. The current configuration uses:

```text
https://cedt-ices.com/
```

The app is opened at `/playground`, while MyCourseVille redirects its OAuth
response to the separately configured root URL:

```text
APP_BASE_PATH=/playground
MCV_REDIRECT_URI=https://cedt-ices.com/
```

For the alternate hostname, set:

```text
MCV_REDIRECT_URI=https://cedt-ies.cp.eng.chula.ac.th/
```

Only one value is sent in each OAuth request, and it must be an exact match,
including its hostname, path, and trailing slash.

## Run

Node.js 18 or newer is required.

```powershell
npm start
```

For local development with the production configuration, open
<http://localhost:3000/playground>. Note that after
authorization MyCourseVille will redirect to the configured public HTTPS
domain, where this same app must be deployed and reachable.

In production, open <https://cedt-ices.com/playground> and click
**Connect MyCourseVille**.

To deploy with the same host-port convention as the earlier Gemini project:

```bash
docker compose up -d --build
```

This publishes container port `3000` on host port `3001` by default.

## Security notes

- `.env` contains credentials and is excluded from Git.
- The client secret is used only by the Node server.
- OAuth tokens are held only in memory and are cleared when the server restarts.
- Token values displayed in the browser are redacted.
- The session cookie is `HttpOnly`, `SameSite=Lax`, and automatically `Secure`
  when the configured callback uses HTTPS.
- App responses include restrictive CSP, cache, permissions, referrer, framing,
  and MIME-sniffing headers. Your HTTPS reverse proxy or Cloudflare can add HSTS.

## API endpoints used

- Authorization: `https://www.mycourseville.com/api/oauth/authorize`
- Token and refresh: `https://www.mycourseville.com/api/oauth/access_token`
- Current user: `https://www.mycourseville.com/api/v1/public/users/me`
- Logout: `https://www.mycourseville.com/api/logout`
