const $ = (id) => document.getElementById(id);

const statusBadge = $("statusBadge");
const statusBadgeText = statusBadge.querySelector(".status-text");
const configWarningCard = $("configWarningCard");
const connectCard = $("connectCard");
const sessionCard = $("sessionCard");
const profilePlaceholder = $("profilePlaceholder");
const profileContent = $("profileContent");
const consoleBody = $("consoleBody");
const accessTokenField = $("accessTokenField");
const refreshTokenField = $("refreshTokenField");
const refreshBtn = $("refreshBtn");
let sessionTimer;

function log(type, message) {
  const line = document.createElement("div");
  line.className = `console-line ${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  consoleBody.appendChild(line);
  consoleBody.scrollTop = consoleBody.scrollHeight;
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

async function checkConfig() {
  try {
    log("system", "Checking backend configuration...");
    const config = await getJson("api/config-check");
    if (!config.configured) {
      statusBadge.className = "connection-status-badge error";
      statusBadgeText.textContent = "Missing Env Config";
      configWarningCard.style.display = "block";
      connectCard.style.display = "none";
      return;
    }

    configWarningCard.style.display = "none";
    $("displayClientId").textContent = config.clientId;
    $("displayRedirectUri").textContent = config.redirectUri;
    log("success", "Backend configuration is ready.");
    await checkSession();
  } catch (error) {
    statusBadge.className = "connection-status-badge error";
    statusBadgeText.textContent = "Server Offline";
    log("error", error.message);
  }
}

async function checkSession() {
  const session = await getJson("api/session-info");
  if (session.error) log("error", session.error);

  if (!session.loggedIn) {
    statusBadge.className = "connection-status-badge configured";
    statusBadgeText.textContent = "Ready to Connect";
    connectCard.style.display = "block";
    sessionCard.style.display = "none";
    profilePlaceholder.style.display = "flex";
    profileContent.style.display = "none";
    log("info", "No active OAuth session.");
    return;
  }

  statusBadge.className = "connection-status-badge connected";
  statusBadgeText.textContent = "Connected";
  connectCard.style.display = "none";
  sessionCard.style.display = "block";
  accessTokenField.value = session.tokens_masked.access_token;
  refreshTokenField.value = session.tokens_masked.refresh_token;
  startExpiryCountdown(session.expires_in_seconds);
  log("success", "Active OAuth session found.");
  await fetchUserProfile();
}

async function fetchUserProfile() {
  try {
    log("action", "Calling GET /users/me...");
    const result = await getJson("api/user");
    const user = result.user || {};
    const englishName = [user.title_en, user.firstname_en, user.lastname_en]
      .filter(Boolean)
      .join(" ");
    const thaiName = [user.title_th, user.firstname_th, user.lastname_th]
      .filter(Boolean)
      .join(" ");
    profilePlaceholder.style.display = "none";
    profileContent.style.display = "block";
    $("userFullName").textContent =
      user.name || englishName || thaiName || user.firstname || "MyCourseVille User";
    $("userEmail").textContent = user.email || "N/A";
    $("userIdField").textContent = user.id || user.uid || "N/A";
    $("userUsernameField").textContent =
      user.username || user.student_id || user.uid || "N/A";
    $("userAvatar").src =
      user.avatar ||
      user.avatar_url ||
      user.profile_image ||
      user.image ||
      `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(user.id || englishName || "mcv")}`;
    $("rawJsonResponse").textContent = JSON.stringify(result.raw || user, null, 2);

    const limit = Number(result.rateLimit?.limit || 60);
    const remaining = Number(result.rateLimit?.remaining || limit);
    $("rateLimitText").textContent = `${remaining} / ${limit}`;
    $("rateLimitFill").style.width = `${Math.max(0, Math.min(100, (remaining / limit) * 100))}%`;
    log("success", "Profile retrieved successfully.");
  } catch (error) {
    log("error", error.message);
  }
}

function startExpiryCountdown(seconds) {
  clearInterval(sessionTimer);
  let remaining = Number(seconds || 0);
  const render = () => {
    const field = $("sessionExpiry");
    if (remaining <= 0) {
      field.textContent = "Expired";
      field.className = "stat-value text-danger";
      $("tokenStatus").textContent = "Expired";
      return;
    }
    field.textContent = `${Math.floor(remaining / 60)}m ${remaining % 60}s`;
    field.className = "stat-value highlight";
    remaining -= 1;
  };
  render();
  sessionTimer = setInterval(render, 1000);
}

async function refreshToken() {
  refreshBtn.disabled = true;
  try {
    log("action", "Refreshing access token...");
    const result = await getJson("api/refresh", { method: "POST" });
    log("success", `Token refreshed; TTL ${result.expires_in} seconds.`);
    await checkSession();
  } catch (error) {
    log("error", error.message);
  } finally {
    refreshBtn.disabled = false;
  }
}

function copyText(text, label) {
  navigator.clipboard.writeText(text).then(
    () => log("info", `Copied ${label}.`),
    (error) => log("error", `Copy failed: ${error.message}`),
  );
}

$("toggleAccessToken").disabled = true;
$("toggleRefreshToken").disabled = true;
$("toggleAccessToken").title = "Full tokens remain server-side";
$("toggleRefreshToken").title = "Full tokens remain server-side";
$("copyAccessToken").addEventListener("click", () =>
  copyText(accessTokenField.value, "masked access token"),
);
$("copyRefreshToken").addEventListener("click", () =>
  copyText(refreshTokenField.value, "masked refresh token"),
);
$("copyRawJson").addEventListener("click", () =>
  copyText($("rawJsonResponse").textContent, "profile JSON"),
);
refreshBtn.addEventListener("click", refreshToken);
$("clearConsoleBtn").addEventListener("click", () => {
  consoleBody.innerHTML = "";
  log("system", "Log cleared.");
});

document.addEventListener("DOMContentLoaded", checkConfig);
