const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

loadEnv(path.join(__dirname, ".env"));
const PUBLIC_DIR = path.join(__dirname, "public");

const PORT = Number(process.env.PORT || 3000);
const CLIENT_ID = process.env.MCV_CLIENT_ID;
const CLIENT_SECRET = process.env.MCV_CLIENT_SECRET;
const REDIRECT_URI =
  process.env.MCV_REDIRECT_URI ||
  process.env.REDIRECT_URI ||
  `http://localhost:${PORT}/oauth/callback`;
const SCOPE = process.env.MCV_SCOPE || "public";
const USE_SECURE_COOKIE = REDIRECT_URI.startsWith("https://");
const REDIRECT_PATH = new URL(REDIRECT_URI).pathname.replace(/\/+$/, "") || "/";
const BASE_PATH = normalizeBasePath(
  process.env.APP_BASE_PATH ??
    (REDIRECT_PATH === "/oauth/callback" || REDIRECT_PATH === "/"
      ? ""
      : REDIRECT_PATH),
);
const COOKIE_PATH =
  BASE_PATH &&
  REDIRECT_PATH !== "/" &&
  (REDIRECT_PATH === BASE_PATH || REDIRECT_PATH.startsWith(`${BASE_PATH}/`))
    ? BASE_PATH
    : "/";

function normalizeBasePath(value) {
  if (!value || value === "/") return "";
  return `/${value.replace(/^\/+|\/+$/g, "")}`;
}

function appPath(pathname = "") {
  if (!pathname) return BASE_PATH ? `${BASE_PATH}/` : "/";
  const suffix = pathname && !pathname.startsWith("/") ? `/${pathname}` : pathname;
  return `${BASE_PATH}${suffix}` || "/";
}

const AUTHORIZE_URL = "https://www.mycourseville.com/api/oauth/authorize";
const TOKEN_URL = "https://www.mycourseville.com/api/oauth/access_token";
const USER_URL = "https://www.mycourseville.com/api/v1/public/users/me";
const LOGOUT_URL = "https://www.mycourseville.com/api/logout";

// This is a local testing app, so an in-memory session store keeps setup simple.
// Restarting the server intentionally clears all sessions and tokens.
const sessions = new Map();

function loadEnv(file) {
  if (!fs.existsSync(file)) return;

  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 0) continue;

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

function parseCookies(req) {
  const cookies = {};
  for (const item of (req.headers.cookie || "").split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    cookies[item.slice(0, separator).trim()] = decodeURIComponent(
      item.slice(separator + 1).trim(),
    );
  }
  return cookies;
}

function getSession(req, res) {
  const cookies = parseCookies(req);
  let id = cookies.mcv_session;

  if (!id || !sessions.has(id)) {
    id = crypto.randomBytes(24).toString("hex");
    sessions.set(id, {});
    res.setHeader(
      "Set-Cookie",
      [
        `mcv_session=${id}`,
        `Path=${COOKIE_PATH}`,
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=86400",
        USE_SECURE_COOKIE ? "Secure" : "",
      ]
        .filter(Boolean)
        .join("; "),
    );
  }

  return sessions.get(id);
}

function send(res, status, body, contentType = "text/plain; charset=utf-8") {
  setSecurityHeaders(res);
  res.writeHead(status, { "Content-Type": contentType });
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8");
}

function sendPublicFile(res, filename, contentType) {
  const file = path.join(PUBLIC_DIR, filename);
  if (!fs.existsSync(file)) return send(res, 404, "Not found");
  return send(res, 200, fs.readFileSync(file), contentType);
}

function redirect(res, location) {
  setSecurityHeaders(res);
  res.writeHead(302, { Location: location });
  res.end();
}

function setSecurityHeaders(res) {
  res.setHeader("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate");
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
  ].join("; "));
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function redactTokens(value) {
  if (!value || typeof value !== "object") return value;
  const copy = Array.isArray(value) ? [] : {};
  for (const [key, item] of Object.entries(value)) {
    if (/^(access_token|refresh_token|client_secret)$/i.test(key)) {
      copy[key] =
        typeof item === "string" && item.length > 10
          ? `${item.slice(0, 5)}…${item.slice(-4)}`
          : "[redacted]";
    } else {
      copy[key] = item && typeof item === "object" ? redactTokens(item) : item;
    }
  }
  return copy;
}

function layout(content) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MyCourseVille OAuth Playground</title>
    <style>
      :root { color-scheme: light dark; font-family: Inter, system-ui, sans-serif; }
      body { margin: 0; background: #0b1020; color: #e8ecf7; }
      main { width: min(760px, calc(100% - 32px)); margin: 56px auto; }
      .card { background: #151c31; border: 1px solid #2a3554; border-radius: 18px;
        padding: 28px; box-shadow: 0 20px 55px #0005; }
      h1 { margin: 0 0 8px; font-size: clamp(1.7rem, 5vw, 2.5rem); }
      h2 { margin-top: 28px; font-size: 1.05rem; }
      p { color: #b9c3dc; line-height: 1.6; }
      .status { display: inline-flex; padding: 6px 10px; border-radius: 999px;
        background: #26304b; color: #cbd5ee; font-size: .85rem; }
      .status.ok { background: #143c2d; color: #8ff0bd; }
      .actions { display: flex; flex-wrap: wrap; gap: 10px; margin: 22px 0; }
      a.button, button { border: 0; border-radius: 10px; padding: 11px 15px;
        background: #6d73ff; color: white; font: inherit; font-weight: 700;
        text-decoration: none; cursor: pointer; }
      a.secondary, button.secondary { background: #293451; }
      button.danger { background: #9b354b; }
      pre { overflow: auto; background: #0b1020; border: 1px solid #2a3554;
        border-radius: 12px; padding: 16px; color: #cfe2ff; line-height: 1.5; }
      code { overflow-wrap: anywhere; }
      .meta { display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px;
        padding: 16px; background: #10172a; border-radius: 12px; }
      .meta span:nth-child(odd) { color: #8997b8; }
      .error { border-left: 4px solid #ff6b7f; padding: 10px 14px;
        background: #401c27; color: #ffd5dc; border-radius: 8px; }
      footer { margin-top: 22px; color: #71809f; font-size: .85rem; }
    </style>
  </head>
  <body><main><section class="card">${content}</section></main></body>
</html>`;
}

function renderHome(session) {
  const connected = Boolean(session.token?.access_token);
  const tokenSummary = session.token
    ? JSON.stringify(redactTokens(session.token), null, 2)
    : "No token acquired yet.";
  const result = session.lastResult
    ? `<h2>Last API response</h2><pre>${escapeHtml(
        JSON.stringify(redactTokens(session.lastResult), null, 2),
      )}</pre>`
    : "";
  const error = session.error
    ? `<div class="error">${escapeHtml(session.error)}</div>`
    : "";

  return layout(`
    <span class="status ${connected ? "ok" : ""}">
      ${connected ? "Connected" : "Not connected"}
    </span>
    <h1>MyCourseVille OAuth Playground</h1>
    <p>Authorize this local app, inspect the token exchange, and test the public
      <code>/users/me</code> endpoint.</p>
    ${error}
    <div class="actions">
      ${
        connected
          ? `<form method="post" action="${escapeHtml(appPath("/api/me"))}"><button>Call /users/me</button></form>
             <form method="post" action="${escapeHtml(appPath("/refresh"))}"><button class="secondary">Refresh token</button></form>
             <form method="post" action="${escapeHtml(appPath("/logout"))}"><button class="danger">Clear session & log out</button></form>`
          : `<a class="button" href="${escapeHtml(appPath("/login"))}">Connect MyCourseVille</a>`
      }
    </div>
    <h2>Configuration</h2>
    <div class="meta">
      <span>Client ID</span><code>${escapeHtml(
        CLIENT_ID ? `${CLIENT_ID.slice(0, 8)}…` : "Missing",
      )}</code>
      <span>Redirect URI</span><code>${escapeHtml(REDIRECT_URI)}</code>
      <span>Scope</span><code>${escapeHtml(SCOPE)}</code>
    </div>
    <h2>Token response (redacted)</h2>
    <pre>${escapeHtml(tokenSummary)}</pre>
    ${result}
    <footer>Tokens are stored only in server memory and disappear when the app restarts.</footer>
  `);
}

async function requestToken(parameters) {
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(parameters),
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    throw new Error(
      `Token request failed (${response.status}): ${JSON.stringify(
        redactTokens(data),
      )}`,
    );
  }
  return data;
}

function storeToken(session, token) {
  const createdAt = Date.now();
  session.token = {
    ...token,
    created_at: createdAt,
    expires_at: createdAt + Number(token.expires_in || 0) * 1000,
  };
}

function tokenPreview(token) {
  if (!token) return null;
  const mask = (value) =>
    typeof value === "string" && value.length > 12
      ? `${value.slice(0, 6)}...${value.slice(-6)}`
      : "[redacted]";
  return {
    access_token: mask(token.access_token),
    refresh_token: mask(token.refresh_token),
  };
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || `localhost:${PORT}`}`);
  const session = getSession(req, res);
  const isRedirectCallback =
    req.method === "GET" &&
    url.pathname === REDIRECT_PATH &&
    (url.searchParams.has("code") || url.searchParams.has("error"));

  if (isRedirectCallback) {
    return handleOAuthCallback(url, session, res);
  }

  const routePath =
    BASE_PATH && url.pathname.startsWith(`${BASE_PATH}/`)
      ? url.pathname.slice(BASE_PATH.length)
      : url.pathname === BASE_PATH
        ? "/"
        : url.pathname;

  if (req.method === "GET" && routePath === "/") {
    if (BASE_PATH && url.pathname === BASE_PATH) {
      return redirect(res, appPath());
    }
    return sendPublicFile(res, "index.html", "text/html; charset=utf-8");
  }

  if (req.method === "GET" && routePath === "/style.css") {
    return sendPublicFile(res, "style.css", "text/css; charset=utf-8");
  }

  if (req.method === "GET" && routePath === "/app.js") {
    return sendPublicFile(res, "app.js", "text/javascript; charset=utf-8");
  }

  if (req.method === "GET" && routePath === "/api/config-check") {
    return sendJson(res, 200, {
      configured: Boolean(CLIENT_ID && CLIENT_SECRET),
      clientId: CLIENT_ID ? `${CLIENT_ID.slice(0, 8)}...` : null,
      redirectUri: REDIRECT_URI,
      scope: SCOPE,
    });
  }

  if (req.method === "GET" && routePath === "/api/session-info") {
    if (!session.token?.access_token) {
      return sendJson(res, 200, {
        loggedIn: false,
        error: session.error || null,
      });
    }

    return sendJson(res, 200, {
      loggedIn: true,
      expires_in_seconds: Math.max(
        0,
        Math.round((session.token.expires_at - Date.now()) / 1000),
      ),
      created_at: new Date(session.token.created_at).toISOString(),
      expires_at: new Date(session.token.expires_at).toISOString(),
      tokens_masked: tokenPreview(session.token),
      error: session.error || null,
    });
  }

  if (req.method === "GET" && routePath === "/api/user") {
    if (!session.token?.access_token) {
      return sendJson(res, 401, { error: "Unauthorized. No active session." });
    }

    try {
      const response = await fetch(USER_URL, {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${session.token.access_token}`,
        },
      });
      const text = await response.text();
      let user;
      try {
        user = text ? JSON.parse(text) : null;
      } catch {
        user = { raw: text };
      }
      if (!response.ok) {
        return sendJson(res, response.status, {
          error: "MyCourseVille profile request failed.",
          details: user,
        });
      }
      return sendJson(res, 200, {
        user,
        rateLimit: {
          limit: response.headers.get("x-ratelimit-limit"),
          remaining: response.headers.get("x-ratelimit-remaining"),
        },
      });
    } catch (error) {
      return sendJson(res, 502, {
        error: "Unable to reach the MyCourseVille API.",
        details: error.message,
      });
    }
  }

  if (req.method === "GET" && routePath === "/login") {
    if (!CLIENT_ID || !CLIENT_SECRET) {
      session.error = "Missing MCV_CLIENT_ID or MCV_CLIENT_SECRET in .env.";
      return redirect(res, appPath());
    }

    session.oauthState = crypto.randomBytes(24).toString("hex");
    const authorize = new URL(AUTHORIZE_URL);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state: session.oauthState,
    }).toString();
    return redirect(res, authorize.toString());
  }

  if (req.method === "GET" && routePath === "/oauth/callback") {
    return handleOAuthCallback(url, session, res);
  }

  if (req.method === "GET" && routePath === "/callback") {
    return handleOAuthCallback(url, session, res);
  }

  if (req.method === "POST" && routePath === "/api/refresh") {
    if (!session.token?.refresh_token) {
      return sendJson(res, 400, { error: "No refresh token is available." });
    }
    try {
      const refreshed = await requestToken({
        grant_type: "refresh_token",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: session.token.refresh_token,
      });
      if (!refreshed.refresh_token) {
        refreshed.refresh_token = session.token.refresh_token;
      }
      storeToken(session, refreshed);
      return sendJson(res, 200, {
        success: true,
        expires_in: refreshed.expires_in,
      });
    } catch (error) {
      return sendJson(res, 502, { error: error.message });
    }
  }

  if (req.method === "POST" && routePath === "/api/me") {
    if (!session.token?.access_token) {
      session.error = "Connect MyCourseVille before calling the API.";
      return redirect(res, appPath());
    }

    try {
      const response = await fetch(USER_URL, {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${session.token.access_token}`,
        },
      });
      const text = await response.text();
      let body;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = text;
      }
      session.lastResult = {
        status: response.status,
        statusText: response.statusText,
        rateLimit: {
          limit: response.headers.get("x-ratelimit-limit"),
          remaining: response.headers.get("x-ratelimit-remaining"),
        },
        body,
      };
    } catch (error) {
      session.error = `API request failed: ${error.message}`;
    }
    return redirect(res, appPath());
  }

  if (req.method === "POST" && routePath === "/refresh") {
    if (!session.token?.refresh_token) {
      session.error = "No refresh token is available.";
      return redirect(res, appPath());
    }

    try {
      const refreshed = await requestToken({
        grant_type: "refresh_token",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: session.token.refresh_token,
      });
      if (!refreshed.refresh_token) {
        refreshed.refresh_token = session.token.refresh_token;
      }
      storeToken(session, refreshed);
    } catch (error) {
      session.error = error.message;
    }
    return redirect(res, appPath());
  }

  if (req.method === "POST" && routePath === "/logout") {
    delete session.token;
    delete session.lastResult;
    return redirect(res, LOGOUT_URL);
  }

  if (req.method === "GET" && routePath === "/logout") {
    delete session.token;
    delete session.lastResult;
    delete session.error;
    return redirect(res, LOGOUT_URL);
  }

  return send(res, 404, "Not found");
}

async function handleOAuthCallback(url, session, res) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    session.error = `Authorization failed: ${oauthError}`;
    return redirect(res, appPath());
  }
  if (!code) {
    session.error = "The callback did not include an authorization code.";
    return redirect(res, appPath());
  }
  if (!state || state !== session.oauthState) {
    session.error = "OAuth state validation failed. Please try connecting again.";
    return redirect(res, appPath());
  }

  delete session.oauthState;
  try {
    const token = await requestToken({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code,
    });
    storeToken(session, token);
    session.lastResult = undefined;
    session.error = undefined;
  } catch (error) {
    session.error = error.message;
  }
  return redirect(res, appPath());
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error(error);
    if (!res.headersSent) {
      send(res, 500, "Unexpected server error");
    } else {
      res.end();
    }
  });
});

server.listen(PORT, () => {
  console.log(`MyCourseVille OAuth Playground: http://localhost:${PORT}${appPath()}`);
  console.log(`OAuth callback: ${REDIRECT_URI}`);
});
