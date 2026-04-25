/**
 * Vaulte Privé relay — production-oriented opaque message store.
 * Never decrypts ciphertext; validates shape + anti-plaintext heuristic only.
 */

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const http2 = require("http2");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const MIN_CIPHERTEXT_BYTES = 1;
const MAX_CIPHERTEXT_BYTES = 256 * 1024;
const PAD_BATCH_DEFAULT_TTL_SEC = Number(process.env.PAD_BATCH_DEFAULT_TTL_SEC || 86400);
const PAD_BATCH_MAX_PADS = Number(process.env.PAD_BATCH_MAX_PADS || 100);
const PAD_BATCH_SWEEP_INTERVAL_SEC = Number(process.env.PAD_BATCH_SWEEP_INTERVAL_SEC || 3600);
const AUTH_CHALLENGE_TTL_SEC = Number(process.env.AUTH_CHALLENGE_TTL_SEC || 120);
const AUTH_CODE_TTL_SEC = Number(process.env.AUTH_CODE_TTL_SEC || 180);

const DATABASE_URL = process.env.DATABASE_URL;
const RELAY_API_KEY = process.env.RELAY_API_KEY?.trim();
const RELAY_HMAC_SECRET = process.env.RELAY_HMAC_SECRET?.trim();
const RELAY_HMAC_WINDOW_SEC = Number(process.env.RELAY_HMAC_WINDOW_SEC || 300);
/** Optional bearer for aggregate admin routes (`X-Relay-Admin-Token`). No message bodies are ever returned. */
const RELAY_ADMIN_TOKEN = process.env.RELAY_ADMIN_TOKEN?.trim();

const RELAY_ALLOWED_ORIGINS = process.env.RELAY_ALLOWED_ORIGINS?.split(",")
  .map((s) => s.trim())
  .filter(Boolean);
/** Max JSON body (avatars, pad-batches). Default 12mb — was 1mb and caused PUT /users … "request entity too large". */
const RELAY_JSON_BODY_LIMIT = process.env.RELAY_JSON_BODY_LIMIT?.trim() || "12mb";
const APNS_TEAM_ID = process.env.APNS_TEAM_ID?.trim();
const APNS_KEY_ID = process.env.APNS_KEY_ID?.trim();
const APNS_BUNDLE_ID = process.env.APNS_BUNDLE_ID?.trim();
const APNS_AUTH_KEY_P8 = process.env.APNS_AUTH_KEY_P8?.replace(/\\n/g, "\n").trim();
const APNS_USE_SANDBOX = String(process.env.APNS_USE_SANDBOX || "").trim() === "1";
const APNS_HOST = APNS_USE_SANDBOX ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";

// Render / reverse proxies
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 1));

// --- PostgreSQL pool (Supabase) ---
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PG_CA_CERT
    ? { ca: require("fs").readFileSync(process.env.PG_CA_CERT, "utf8") }
    : { rejectUnauthorized: false },
  max: Number(process.env.PG_POOL_MAX || 20),
  idleTimeoutMillis: Number(process.env.PG_IDLE_MS || 30_000),
  connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT_MS || 10_000),
});

pool.on("error", (err) => {
  log("error", "idle_pg_client", { message: err.message });
});

// --- Middleware: request id + JSON + security headers ---
app.use((req, res, next) => {
  const rid =
    req.headers["x-request-id"] ||
    `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  req.id = rid;
  res.setHeader("X-Request-Id", rid);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "interest-cohort=()");
  next();
});

app.use(
  cors({
    origin:
      RELAY_ALLOWED_ORIGINS && RELAY_ALLOWED_ORIGINS.length > 0
        ? RELAY_ALLOWED_ORIGINS
        : true,
    maxAge: 86400,
  })
);

app.use(
  express.json({
    limit: RELAY_JSON_BODY_LIMIT,
    verify: (req, _res, buf) => {
      req.rawBody = Buffer.from(buf);
    },
  })
);

// --- Optional API key (set RELAY_API_KEY on Render; app sends X-API-Key or Authorization: Bearer) ---
function requireApiKey(req, res, next) {
  if (!RELAY_API_KEY) return next();
  const h = req.headers.authorization;
  const x = req.headers["x-api-key"];
  const bearer =
    typeof h === "string" && h.toLowerCase().startsWith("bearer ")
      ? h.slice(7).trim()
      : null;
  const token = bearer || (typeof x === "string" ? x.trim() : "");
  const tokenBuf = Buffer.from(token);
  const keyBuf = Buffer.from(RELAY_API_KEY);
  if (tokenBuf.length !== keyBuf.length || !crypto.timingSafeEqual(tokenBuf, keyBuf)) {
    return res.status(401).json({ error: "unauthorized", request_id: req.id });
  }
  next();
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (aa.length === 0 || bb.length === 0) return false;
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function timingSafeEqualUtf8(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function requireRelayAdmin(req, res, next) {
  if (!RELAY_ADMIN_TOKEN) {
    return res.status(503).json({ error: "admin_disabled", request_id: req.id });
  }
  const h = req.headers["x-relay-admin-token"];
  if (typeof h !== "string" || !timingSafeEqualUtf8(h, RELAY_ADMIN_TOKEN)) {
    return res.status(401).json({ error: "admin_unauthorized", request_id: req.id });
  }
  next();
}

function canonicalizeURL(originalUrl) {
  const [path, queryString = ""] = String(originalUrl || "").split("?");
  if (!queryString) return path;
  const params = new URLSearchParams(queryString);
  const sorted = [...params.entries()].sort(([ak, av], [bk, bv]) =>
    ak === bk ? av.localeCompare(bv) : ak.localeCompare(bk)
  );
  const canonicalQuery = new URLSearchParams(sorted).toString();
  return canonicalQuery ? `${path}?${canonicalQuery}` : path;
}

/**
 * Optional tamper/replay protection:
 * X-Relay-Timestamp: unix seconds
 * X-Relay-Signature: hex(HMAC_SHA256(secret, `${ts}.${method}.${path}.${rawBody}`))
 */
function requireRelaySignature(req, res, next) {
  if (!RELAY_HMAC_SECRET) return next();
  const tsRaw = req.headers["x-relay-timestamp"];
  const sig = req.headers["x-relay-signature"];
  if (typeof tsRaw !== "string" || typeof sig !== "string") {
    return res.status(401).json({ error: "missing_signature", request_id: req.id });
  }
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts)) {
    return res.status(401).json({ error: "invalid_signature_timestamp", request_id: req.id });
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > RELAY_HMAC_WINDOW_SEC) {
    return res.status(401).json({ error: "signature_expired", request_id: req.id });
  }

  const raw = req.rawBody ? req.rawBody.toString("utf8") : "";
  const canonicalPath = canonicalizeURL(req.originalUrl);
  const canonical = `${ts}.${req.method.toUpperCase()}.${canonicalPath}.${raw}`;
  const expected = crypto.createHmac("sha256", RELAY_HMAC_SECRET).update(canonical).digest("hex");
  if (!timingSafeEqualHex(expected, sig)) {
    return res.status(401).json({ error: "bad_signature", request_id: req.id });
  }
  next();
}

// --- Rate limits (per IP; behind trust proxy uses real client IP) ---
const postMessageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_POST_PER_MIN || 120),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: "rate_limit_exceeded",
      retry_after_seconds: 60,
      request_id: req.id,
    });
  },
});

const getMessagesLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_GET_PER_MIN || 300),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: "rate_limit_exceeded",
      retry_after_seconds: 60,
      request_id: req.id,
    });
  },
});

function log(level, event, fields = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...fields,
  });
  if (level === "error") console.error(line);
  else console.log(line);
}

function hasApnsConfig() {
  return Boolean(APNS_TEAM_ID && APNS_KEY_ID && APNS_BUNDLE_ID && APNS_AUTH_KEY_P8);
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makeApnsJwt() {
  if (!hasApnsConfig()) return null;
  const header = base64UrlEncode(JSON.stringify({ alg: "ES256", kid: APNS_KEY_ID }));
  const issuedAt = Math.floor(Date.now() / 1000);
  const claims = base64UrlEncode(JSON.stringify({ iss: APNS_TEAM_ID, iat: issuedAt }));
  const unsigned = `${header}.${claims}`;
  const signer = crypto.createSign("sha256");
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(APNS_AUTH_KEY_P8);
  return `${unsigned}.${base64UrlEncode(signature)}`;
}

async function deletePushToken(userId, deviceToken) {
  try {
    await pool.query(
      `DELETE FROM user_push_tokens
       WHERE user_id = $1::uuid AND device_token = $2`,
      [userId, deviceToken]
    );
  } catch (e) {
    log("warn", "push_token_delete_failed", { userId, message: e.message });
  }
}

async function sendApnsToDevice(userId, deviceToken, payload, topic) {
  const jwt = makeApnsJwt();
  if (!jwt) return false;

  return new Promise((resolve) => {
    const client = http2.connect(APNS_HOST);
    let statusCode = 0;
    let responseBody = "";
    const req = client.request({
      ":method": "POST",
      ":path": `/3/device/${deviceToken}`,
      authorization: `bearer ${jwt}`,
      "apns-topic": topic || APNS_BUNDLE_ID,
      "apns-push-type": "alert",
      "apns-priority": "10",
      "content-type": "application/json",
    });

    req.setEncoding("utf8");
    req.on("response", (headers) => {
      statusCode = Number(headers[":status"] || 0);
    });
    req.on("data", (chunk) => {
      responseBody += chunk;
    });
    req.on("end", async () => {
      client.close();
      if (statusCode >= 200 && statusCode < 300) {
        resolve(true);
        return;
      }
      let reason = "";
      try {
        reason = String(JSON.parse(responseBody || "{}").reason || "");
      } catch {}
      if (["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"].includes(reason)) {
        await deletePushToken(userId, deviceToken);
      }
      log("warn", "apns_send_failed", { userId, statusCode, reason });
      resolve(false);
    });
    req.on("error", (error) => {
      client.close();
      log("warn", "apns_transport_error", { userId, message: error.message });
      resolve(false);
    });
    req.end(JSON.stringify(payload));
  });
}

async function pushGenericNewMessageNotification({ recipientId, senderId, conversationId, messageId, kind = "message" }) {
  if (!hasApnsConfig()) return;
  try {
    const result = await pool.query(
      `SELECT device_token, COALESCE(bundle_id, $2) AS bundle_id
       FROM user_push_tokens
       WHERE user_id = $1::uuid`,
      [recipientId, APNS_BUNDLE_ID]
    );
    if (!result.rows.length) return;
    const payload = {
      aps: {
        alert: {
          title: "Vaulté Privé",
          body: kind === "initial_x3dh" ? "New secure chat request in Vaulté Privé" : "New message in Vaulté Privé",
        },
        sound: "default",
        badge: 1,
      },
      type: kind,
      sender_id: senderId,
      recipient_id: recipientId,
      conversation_id: conversationId,
      message_id: messageId,
    };
    for (const row of result.rows) {
      await sendApnsToDevice(recipientId, String(row.device_token), payload, String(row.bundle_id || APNS_BUNDLE_ID));
    }
  } catch (e) {
    log("warn", "push_notify_failed", { recipientId, message: e.message });
  }
}

// --- VALIDATION ---

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const USERNAME_RE = /^[a-z0-9_]{3,24}$/;
const ETH_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const KEY_TYPE_X25519 = "x25519";
const AUTH_TOKEN_RE = /^[A-Za-z0-9_-]{16,200}$/;
const AUTH_CONNECT_ICONS = [
  "star.fill",
  "moon.fill",
  "bolt.fill",
  "heart.fill",
  "flame.fill",
  "leaf.fill",
  "drop.fill",
  "crown.fill",
  "diamond.fill",
];

function isIsoDate(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function validateOpaqueCipherBase64(b64) {
  let buf;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    return "invalid base64 decode";
  }

  if (buf.length < MIN_CIPHERTEXT_BYTES) return "ciphertext_too_short";
  if (buf.length > MAX_CIPHERTEXT_BYTES) return "ciphertext_too_large";
  return null;
}

function looksLikeE2EPlusEnvelopeBytes(buf) {
  try {
    const text = buf.toString("utf8");
    const obj = JSON.parse(text);
    if (!obj || typeof obj !== "object") return false;

    // v1 e2e_plus envelope
    if (obj.version === 1 && obj.mode === "e2e_plus") {
      if (typeof obj.nonceB64 !== "string") return false;
      if (typeof obj.ciphertextB64 !== "string") return false;
      if (typeof obj.tagB64 !== "string") return false;
      const n = decodeStrictBase64(obj.nonceB64);
      const c = decodeStrictBase64(obj.ciphertextB64);
      const t = decodeStrictBase64(obj.tagB64);
      return Boolean(n && c && t && n.length === 12 && t.length === 16 && c.length > 0);
    }

    // v2 double-AEAD envelope
    if (obj.version === 2 && obj.mode === "svr2_double_aead") {
      return typeof obj.innerNonceB64 === "string" && typeof obj.outerNonceB64 === "string";
    }

    // v4 Double Ratchet envelope
    if (obj.version === 4 && obj.mode === "dr_chacha_v1") {
      if (typeof obj.nonceB64 !== "string") return false;
      if (typeof obj.ciphertextB64 !== "string") return false;
      if (typeof obj.tagB64 !== "string") return false;
      if (!obj.header || typeof obj.header.publicKeyB64 !== "string") return false;
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

function validateMessageDTO(body) {
  const required = [
    "message_id",
    "conversation_id",
    "sender_id",
    "recipient_id",
    "pad_id",
    "ciphertext_base64",
    "created_at",
  ];

  for (const key of required) {
    if (!(key in body)) return `missing field: ${key}`;
  }

  const uuidFields = [
    "message_id",
    "conversation_id",
    "sender_id",
    "recipient_id",
    "pad_id",
  ];

  for (const key of uuidFields) {
    if (typeof body[key] !== "string" || !UUID_RE.test(body[key])) {
      return `invalid uuid: ${key}`;
    }
  }

  if (typeof body.ciphertext_base64 !== "string" || body.ciphertext_base64.length === 0) {
    return "invalid ciphertext_base64";
  }

  if (!isIsoDate(body.created_at)) {
    return "invalid date";
  }

  return validateOpaqueCipherBase64(body.ciphertext_base64);
}

function normalizeUsername(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim().toLowerCase();
  const withoutPrefix = trimmed.startsWith("@") ? trimmed.slice(1) : trimmed;
  if (!USERNAME_RE.test(withoutPrefix)) return null;
  return withoutPrefix;
}

function decodeStrictBase64(input) {
  if (typeof input !== "string") return null;
  const value = input.trim();
  if (value.length === 0 || value.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  let bytes;
  try {
    bytes = Buffer.from(value, "base64");
  } catch {
  return null;
  }
  if (!bytes || bytes.length === 0) return null;
  if (bytes.toString("base64") !== value) return null;
  return bytes;
}

function validatePublicKeyBase64(b64) {
  const bytes = decodeStrictBase64(b64);
  return Boolean(bytes && bytes.length === 32);
}

function makePadBatchToken() {
  const a = crypto.randomBytes(3).toString("hex").toUpperCase();
  const b = crypto.randomBytes(1).toString("hex").toUpperCase();
  return `VP-${a}-${b}`;
}

function makeAuthToken(bytes = 24) {
  return base64UrlEncode(crypto.randomBytes(bytes));
}

function validateRedirectURI(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol === "https:") return url.toString();
    if (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) {
      return url.toString();
    }
  } catch {}
  return null;
}

function normalizeAuthOrigin(raw, redirectURI) {
  if (typeof raw === "string" && raw.trim().length > 0) {
    return raw.trim().slice(0, 160);
  }
  try {
    return new URL(redirectURI).host.slice(0, 160);
  } catch {
    return "unknown";
  }
}

function makeEmojiChallengeIcons() {
  const pool = [...AUTH_CONNECT_ICONS];
  const icons = [];
  while (pool.length > 0 && icons.length < 3) {
    const idx = Math.floor(Math.random() * pool.length);
    icons.push(pool.splice(idx, 1)[0]);
  }
  const correctIcon = icons[Math.floor(Math.random() * icons.length)] || AUTH_CONNECT_ICONS[0];
  return { icons, correctIcon };
}

function validatePadBatchBody(body) {
  if (!body || typeof body !== "object") return "invalid_body";
  if (!UUID_RE.test(body.conversation_id)) return "invalid_conversation_id";
  if (body.direction !== "inbound" && body.direction !== "outbound") return "invalid_direction";
  if (!Array.isArray(body.pads) || body.pads.length === 0) return "invalid_pads";
  if (body.pads.length > PAD_BATCH_MAX_PADS) return "pads_limit_exceeded";
  for (const p of body.pads) {
    if (!p || typeof p !== "object") return "invalid_pad_entry";
    if (!UUID_RE.test(p.id)) return "invalid_pad_id";
    if (typeof p.bytes_b64 !== "string" || p.bytes_b64.length === 0) return "invalid_pad_bytes";
    const bytes = decodeStrictBase64(p.bytes_b64);
    if (!bytes) return "invalid_pad_bytes";
    if (!bytes || bytes.length < 16 || bytes.length > 4096) return "invalid_pad_bytes_length";
    if (!isIsoDate(p.created_at)) return "invalid_pad_created_at";
  }
  if (body.owner_user_id && !UUID_RE.test(body.owner_user_id)) return "invalid_owner_user_id";
  if (body.ttl_seconds !== undefined) {
    const ttl = Number(body.ttl_seconds);
    if (!Number.isFinite(ttl) || ttl < 60 || ttl > 30 * 24 * 3600) return "invalid_ttl_seconds";
  }
  return null;
}

function validateInitialX3DHMessageDTO(body) {
  const required = [
    "message_id",
    "conversation_id",
    "sender_id",
    "recipient_id",
    "identity_key",
    "ephemeral_key",
    "signed_prekey_id",
    "ciphertext_base64",
    "created_at",
  ];
  for (const key of required) {
    if (!(key in body)) return `missing field: ${key}`;
  }
  const uuidFields = ["message_id", "conversation_id", "sender_id", "recipient_id"];
  for (const key of uuidFields) {
    if (typeof body[key] !== "string" || !UUID_RE.test(body[key])) {
      return `invalid uuid: ${key}`;
    }
  }
  if (!validatePublicKeyBase64(body.identity_key)) return "invalid_identity_key";
  if (!validatePublicKeyBase64(body.ephemeral_key)) return "invalid_ephemeral_key";
  if (!Number.isInteger(Number(body.signed_prekey_id)) || Number(body.signed_prekey_id) < 0) {
    return "invalid_signed_prekey_id";
  }
  if (
    body.one_time_prekey_id !== undefined &&
    body.one_time_prekey_id !== null &&
    (!Number.isInteger(Number(body.one_time_prekey_id)) || Number(body.one_time_prekey_id) < 0)
  ) {
    return "invalid_one_time_prekey_id";
  }
  if (typeof body.ciphertext_base64 !== "string" || !body.ciphertext_base64.startsWith("e2:")) {
    return "invalid_ciphertext_base64";
  }
  const raw = body.ciphertext_base64.slice(3);
  const err = validateOpaqueCipherBase64(raw);
  if (err) return err;
  if (!isIsoDate(body.created_at)) return "invalid_date";
  return null;
}

async function sweepExpiredPadBatches() {
  try {
    await pool.query(`DELETE FROM pad_batches WHERE expires_at < NOW()`);
  } catch (e) {
    log("error", "sweep_pad_batches_failed", { message: e.message });
  }
}

async function sweepExpiredAuthArtifacts() {
  try {
    await pool.query(`DELETE FROM auth_codes WHERE expires_at < NOW() OR consumed_at IS NOT NULL`);
    await pool.query(`DELETE FROM auth_challenges WHERE expires_at < NOW()`);
  } catch (e) {
    log("error", "sweep_auth_artifacts_failed", { message: e.message });
  }
}

// --- Routes ---

app.get("/", (_req, res) => {
  res.type("text/plain").send("Vaulte relay running");
});

app.get("/healthz", async (_req, res) => {
  res.json({ ok: true, request_id: _req.id });
});

/** Deep health: DB must respond (use for orchestrator / manual checks). */
app.get("/readyz", async (req, res) => {
  try {
    await pool.query("SELECT 1 AS ok");
    return res.json({
      ok: true,
      db: "up",
      request_id: req.id,
    });
  } catch (e) {
    log("error", "readyz_failed", { message: e.message, request_id: req.id });
    return res.status(503).json({
      ok: false,
      db: "down",
      error: "database_unavailable",
      request_id: req.id,
    });
  }
});

app.post("/auth/challenges", requireApiKey, requireRelaySignature, async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const redirectURI = validateRedirectURI(req.body?.redirect_uri);
  const state = typeof req.body?.state === "string" ? req.body.state.trim().slice(0, 512) : "";
  if (!username) {
    return res.status(400).json({ error: "invalid_username", request_id: req.id });
  }
  if (!redirectURI) {
    return res.status(400).json({ error: "invalid_redirect_uri", request_id: req.id });
  }
  const origin = normalizeAuthOrigin(req.body?.origin, redirectURI);
  const { icons, correctIcon } = makeEmojiChallengeIcons();
  const challengeId = makeAuthToken();
  const expiresAt = new Date(Date.now() + AUTH_CHALLENGE_TTL_SEC * 1000).toISOString();

  try {
    const user = await pool.query(
      `SELECT user_id
       FROM users
       WHERE username = $1
       LIMIT 1`,
      [username]
    );
    if (user.rowCount === 0) {
      return res.status(404).json({ error: "user_not_found", request_id: req.id });
    }

    await pool.query(
      `INSERT INTO auth_challenges (
         challenge_id, user_id, origin, redirect_uri, client_state,
         icons_json, correct_icon, status, expires_at
       ) VALUES ($1, $2::uuid, $3, $4, $5, $6::jsonb, $7, 'pending', $8::timestamptz)`,
      [challengeId, user.rows[0].user_id, origin, redirectURI, state, JSON.stringify(icons), correctIcon, expiresAt]
    );

    return res.status(201).json({
      challenge_id: challengeId,
      user_id: user.rows[0].user_id,
      origin,
      icons,
      correct_icon: correctIcon,
      expires_at: expiresAt,
      request_id: req.id,
    });
  } catch (e) {
    log("error", "create_auth_challenge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.get("/auth/challenges/:challengeId", requireApiKey, requireRelaySignature, async (req, res) => {
  const challengeId = String(req.params.challengeId || "").trim();
  if (!AUTH_TOKEN_RE.test(challengeId)) {
    return res.status(400).json({ error: "invalid_challenge_id", request_id: req.id });
  }
  try {
    const r = await pool.query(
      `SELECT challenge_id, user_id, origin, redirect_uri, client_state, icons_json, status, expires_at
       FROM auth_challenges
       WHERE challenge_id = $1
       LIMIT 1`,
      [challengeId]
    );
    if (r.rowCount === 0) {
      return res.status(404).json({ error: "challenge_not_found", request_id: req.id });
    }
    const row = r.rows[0];
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return res.status(410).json({ error: "challenge_expired", request_id: req.id });
    }
    if (row.status !== "pending") {
      return res.status(409).json({ error: "challenge_resolved", status: row.status, request_id: req.id });
    }
    return res.json({
      challenge_id: row.challenge_id,
      user_id: row.user_id,
      origin: row.origin,
      redirect_uri: row.redirect_uri,
      state: row.client_state || "",
      icons: Array.isArray(row.icons_json) ? row.icons_json : [],
      expires_at: row.expires_at,
      request_id: req.id,
    });
  } catch (e) {
    log("error", "get_auth_challenge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.post("/auth/challenges/:challengeId/approve", requireApiKey, requireRelaySignature, async (req, res) => {
  const challengeId = String(req.params.challengeId || "").trim();
  const userId = String(req.body?.user_id || "").trim();
  const selectedIcon = typeof req.body?.selected_icon === "string" ? req.body.selected_icon.trim() : "";
  if (!AUTH_TOKEN_RE.test(challengeId)) {
    return res.status(400).json({ error: "invalid_challenge_id", request_id: req.id });
  }
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  if (!AUTH_CONNECT_ICONS.includes(selectedIcon)) {
    return res.status(400).json({ error: "invalid_selected_icon", request_id: req.id });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `SELECT challenge_id, user_id, redirect_uri, client_state, correct_icon, status, expires_at
       FROM auth_challenges
       WHERE challenge_id = $1
       LIMIT 1
       FOR UPDATE`,
      [challengeId]
    );
    if (r.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "challenge_not_found", request_id: req.id });
    }
    const row = r.rows[0];
    if (String(row.user_id).toLowerCase() !== userId.toLowerCase()) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "challenge_user_mismatch", request_id: req.id });
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      await client.query("ROLLBACK");
      return res.status(410).json({ error: "challenge_expired", request_id: req.id });
    }
    if (row.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "challenge_resolved", status: row.status, request_id: req.id });
    }

    if (selectedIcon !== row.correct_icon) {
      await client.query(
        `UPDATE auth_challenges
         SET status = 'rejected', selected_icon = $2, resolved_at = NOW()
         WHERE challenge_id = $1`,
        [challengeId, selectedIcon]
      );
      await client.query("COMMIT");
      return res.json({ result: "rejected", request_id: req.id });
    }

    const code = makeAuthToken();
    const codeExpiresAt = new Date(Date.now() + AUTH_CODE_TTL_SEC * 1000).toISOString();
    await client.query(
      `INSERT INTO auth_codes (code, challenge_id, user_id, expires_at)
       VALUES ($1, $2, $3::uuid, $4::timestamptz)`,
      [code, challengeId, userId, codeExpiresAt]
    );
    await client.query(
      `UPDATE auth_challenges
       SET status = 'approved',
           selected_icon = $2,
           approved_at = NOW(),
           resolved_at = NOW()
       WHERE challenge_id = $1`,
      [challengeId, selectedIcon]
    );
    await client.query("COMMIT");
    return res.json({
      result: "approved",
      code,
      redirect_uri: row.redirect_uri,
      state: row.client_state || "",
      expires_at: codeExpiresAt,
      request_id: req.id,
    });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    log("error", "approve_auth_challenge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  } finally {
    client.release();
  }
});

app.post("/auth/token", requireApiKey, requireRelaySignature, async (req, res) => {
  const code = String(req.body?.code || "").trim();
  if (!AUTH_TOKEN_RE.test(code)) {
    return res.status(400).json({ error: "invalid_code", request_id: req.id });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `SELECT c.code, c.challenge_id, c.user_id, c.expires_at, c.consumed_at,
              ch.origin, ch.client_state
       FROM auth_codes c
       JOIN auth_challenges ch ON ch.challenge_id = c.challenge_id
       WHERE c.code = $1
       LIMIT 1
       FOR UPDATE`,
      [code]
    );
    if (r.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "code_not_found", request_id: req.id });
    }
    const row = r.rows[0];
    if (row.consumed_at) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "code_already_used", request_id: req.id });
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      await client.query("ROLLBACK");
      return res.status(410).json({ error: "code_expired", request_id: req.id });
    }

    await client.query(`UPDATE auth_codes SET consumed_at = NOW() WHERE code = $1`, [code]);
    await client.query(`UPDATE auth_challenges SET status = 'consumed' WHERE challenge_id = $1`, [row.challenge_id]);
    await client.query("COMMIT");
    return res.json({
      user_id: row.user_id,
      challenge_id: row.challenge_id,
      origin: row.origin,
      state: row.client_state || "",
      request_id: req.id,
    });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    log("error", "exchange_auth_code_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  } finally {
    client.release();
  }
});

app.get("/users/resolve", requireApiKey, requireRelaySignature, async (req, res) => {
  const username = normalizeUsername(req.query.username);
  if (!username) {
    return res.status(400).json({ error: "invalid_username", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, username, display_name, avatar_b64, wallet_address, updated_at
       FROM users
       WHERE username = $1
       LIMIT 1`,
      [username]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "user_not_found", request_id: req.id });
    }
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "resolve_user_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.get("/users/search", requireApiKey, requireRelaySignature, async (req, res) => {
  const q = req.query.q;
  const raw = typeof q === "string" ? q.trim().toLowerCase() : "";
  if (raw.length < 2) {
    return res.status(400).json({ error: "query_too_short", request_id: req.id });
  }
  const n = Number(req.query.limit);
  const limit = Math.min(Math.max(Number.isFinite(n) ? Math.floor(n) : 20, 1), 50);
  try {
    const result = await pool.query(
      `SELECT user_id, username, display_name, avatar_b64, wallet_address, updated_at
       FROM users
       WHERE username LIKE $1
       ORDER BY username ASC
       LIMIT $2`,
      [`${raw}%`, limit]
    );
    return res.json(result.rows);
  } catch (e) {
    log("error", "search_user_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.get("/users/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, username, display_name, avatar_b64, wallet_address, updated_at
       FROM users
       WHERE user_id = $1::uuid
       LIMIT 1`,
      [userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "user_not_found", request_id: req.id });
    }
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "get_user_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.put("/users/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }

  let existingRow;
  try {
    const r = await pool.query(
      `SELECT username FROM users WHERE user_id = $1::uuid LIMIT 1`,
      [userId]
    );
    existingRow = r.rows[0];
  } catch (e) {
    log("error", "put_user_prefetch", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }

  // Body may omit username (avatar-only clients); reuse row from DB when present.
  let normalized = normalizeUsername(req.body?.username);
  if (!normalized && existingRow?.username) {
    normalized = normalizeUsername(existingRow.username);
  }
  if (!normalized) {
    return res.status(400).json({ error: "invalid_username", request_id: req.id });
  }



  const displayName = (typeof req.body?.display_name === "string"
    ? req.body.display_name.trim().slice(0, 64)
    : null) || null;

  const avatarInBody = req.body && Object.prototype.hasOwnProperty.call(req.body, "avatar_b64");
  let avatarParam = null;
  if (avatarInBody) {
    const raw = req.body.avatar_b64;
    if (typeof raw !== "string") {
      return res.status(400).json({ error: "invalid_avatar_b64", request_id: req.id });
    }
    const trimmed = raw.trim();
    /** Base64 character cap (relay + Postgres); keep below RELAY_JSON_BODY_LIMIT. */
    const MAX_AVATAR_B64 = 3_500_000;
    if (trimmed.length > MAX_AVATAR_B64) {
      return res.status(400).json({ error: "avatar_too_large", request_id: req.id });
    }
    avatarParam = trimmed.length ? trimmed : null;
  }
  const insertAvatar = avatarInBody ? avatarParam : null;
  const walletInBody = req.body && Object.prototype.hasOwnProperty.call(req.body, "wallet_address");
  let walletParam = null;
  if (walletInBody) {
    const raw = req.body.wallet_address;
    if (typeof raw !== "string") {
      return res.status(400).json({ error: "invalid_wallet_address", request_id: req.id });
    }
    const trimmed = raw.trim();
    if (trimmed.length > 0 && !ETH_ADDRESS_RE.test(trimmed)) {
      return res.status(400).json({ error: "invalid_wallet_address", request_id: req.id });
    }
    walletParam = trimmed.length ? trimmed : null;
  }
  const insertWallet = walletInBody ? walletParam : null;

  try {
    const result = await pool.query(
      `INSERT INTO users (user_id, username, display_name, avatar_b64, wallet_address, updated_at)
       VALUES ($1::uuid, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET username = EXCLUDED.username,
           display_name = COALESCE(EXCLUDED.display_name, users.display_name),
           avatar_b64 = CASE WHEN $6::boolean THEN EXCLUDED.avatar_b64 ELSE users.avatar_b64 END,
           wallet_address = CASE WHEN $7::boolean THEN EXCLUDED.wallet_address ELSE users.wallet_address END,
           updated_at = NOW()
       RETURNING user_id, username, display_name, avatar_b64, wallet_address, updated_at`,
      [userId, normalized, displayName, insertAvatar, insertWallet, avatarInBody, walletInBody]
    );
    return res.json(result.rows[0]);
  } catch (e) {
    if (e && e.code === "23505") {
      return res.status(409).json({ error: "username_taken", request_id: req.id });
    }
    log("error", "put_user_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.delete("/users/:userId/hard-reset", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`DELETE FROM messages WHERE sender_id = $1::uuid OR recipient_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM users WHERE user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM user_identity_keys WHERE user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM signed_prekeys WHERE user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM one_time_prekeys WHERE user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM pad_batches WHERE owner_user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM user_badges WHERE user_id = $1::uuid`, [userId]);
    await client.query(`DELETE FROM user_push_tokens WHERE user_id = $1::uuid`, [userId]);
    await client.query("COMMIT");
    return res.json({ status: "hard_reset_completed", request_id: req.id });
  } catch (e) {
    await client.query("ROLLBACK");
    log("error", "hard_reset_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  } finally {
    client.release();
  }
});

app.put("/users/:userId/push-devices/apns", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const deviceToken = String(req.body?.device_token || "").trim().toLowerCase();
  const bundleId = String(req.body?.bundle_id || "").trim() || APNS_BUNDLE_ID || null;
  if (!/^[0-9a-f]{64,200}$/.test(deviceToken)) {
    return res.status(400).json({ error: "invalid_device_token", request_id: req.id });
  }
  try {
    await pool.query(
      `INSERT INTO user_push_tokens (user_id, device_token, platform, bundle_id, updated_at, last_seen_at)
       VALUES ($1::uuid, $2, 'apns', $3, NOW(), NOW())
       ON CONFLICT (user_id, device_token, platform)
       DO UPDATE SET bundle_id = EXCLUDED.bundle_id,
                     updated_at = NOW(),
                     last_seen_at = NOW()`,
      [userId, deviceToken, bundleId]
    );
    return res.json({ status: "push_device_registered", request_id: req.id });
  } catch (e) {
    log("error", "put_push_device_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.delete("/users/:userId/push-devices/apns/:deviceToken", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId, deviceToken } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const normalized = String(deviceToken || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64,200}$/.test(normalized)) {
    return res.status(400).json({ error: "invalid_device_token", request_id: req.id });
  }
  try {
    await deletePushToken(userId, normalized);
    return res.json({ status: "push_device_deleted", request_id: req.id });
  } catch (e) {
    log("error", "delete_push_device_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});



// --- Verification badges ---

// GET /badges/:userId — fetch a user's badge (public)
app.get("/badges/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, badge_type, granted_by, granted_at
       FROM user_badges
       WHERE user_id = $1::uuid
       LIMIT 1`,
      [userId]
    );
    if (result.rowCount === 0) {
      return res.json({ user_id: userId, badge_type: null });
    }
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "get_badge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// GET /badges — list all badged users
app.get("/badges", requireApiKey, requireRelaySignature, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.user_id, b.badge_type, b.granted_by, b.granted_at,
              u.username
       FROM user_badges b
       LEFT JOIN users u ON u.user_id = b.user_id
       ORDER BY b.granted_at DESC
       LIMIT 500`
    );
    return res.json({ badges: result.rows });
  } catch (e) {
    log("error", "list_badges_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// PUT /badges/:userId — admin grants or updates a badge
// badge_type: "official" (gold), "verified" (blue), "diamond" (owner tier)
app.put("/badges/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const badgeType = req.body?.badge_type;
  if (!["official", "verified", "diamond"].includes(badgeType)) {
    return res.status(400).json({ error: "invalid_badge_type", valid: ["official", "verified", "diamond"], request_id: req.id });
  }
  const grantedBy = req.body?.granted_by || "system";
  try {
    const result = await pool.query(
      `INSERT INTO user_badges (user_id, badge_type, granted_by, granted_at)
       VALUES ($1::uuid, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET badge_type = EXCLUDED.badge_type,
           granted_by = EXCLUDED.granted_by,
           granted_at = NOW()
       RETURNING user_id, badge_type, granted_by, granted_at`,
      [userId, badgeType, grantedBy]
    );
    log("info", "badge_granted", { user_id: userId, badge_type: badgeType, request_id: req.id });
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "put_badge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// DELETE /badges/:userId — revoke a badge
app.delete("/badges/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    await pool.query(
      `DELETE FROM user_badges WHERE user_id = $1::uuid`,
      [userId]
    );
    log("info", "badge_revoked", { user_id: userId, request_id: req.id });
    return res.json({ user_id: userId, badge_type: null });
  } catch (e) {
    log("error", "delete_badge_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.get("/keys/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, key_type, public_key_base64, signing_public_key_base64, updated_at
       FROM user_identity_keys
       WHERE user_id = $1::uuid
       LIMIT 1`,
      [userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "key_not_found", request_id: req.id });
    }
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "get_identity_key_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.put("/keys/:userId", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const keyType = String(req.body?.key_type || "").trim().toLowerCase();
  const publicKeyBase64 = req.body?.public_key_base64;
  const signingKeyBase64 = req.body?.signing_public_key_base64 || null;
  if (keyType !== KEY_TYPE_X25519) {
    return res.status(400).json({ error: "invalid_key_type", request_id: req.id });
  }
  if (!validatePublicKeyBase64(publicKeyBase64)) {
    return res.status(400).json({ error: "invalid_public_key", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `INSERT INTO user_identity_keys (user_id, key_type, public_key_base64, signing_public_key_base64, updated_at)
       VALUES ($1::uuid, $2, $3, $4, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET key_type = EXCLUDED.key_type,
           public_key_base64 = EXCLUDED.public_key_base64,
           signing_public_key_base64 = COALESCE(EXCLUDED.signing_public_key_base64, user_identity_keys.signing_public_key_base64),
           updated_at = NOW()
       RETURNING user_id, key_type, public_key_base64, signing_public_key_base64, updated_at`,
      [userId, keyType, publicKeyBase64, signingKeyBase64]
    );
    return res.json(result.rows[0]);
  } catch (e) {
    log("error", "put_identity_key_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// ─── Signed Prekeys ─────────────────────────────────────────────────────

// PUT /keys/:userId/signed-prekey — upload or rotate signed prekey
app.put("/keys/:userId/signed-prekey", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const keyId = Number(req.body?.key_id);
  const publicKeyBase64 = req.body?.public_key_base64;
  const signatureBase64 = req.body?.signature_base64;
  if (!Number.isInteger(keyId) || keyId < 0) {
    return res.status(400).json({ error: "invalid_key_id", request_id: req.id });
  }
  if (!validatePublicKeyBase64(publicKeyBase64)) {
    return res.status(400).json({ error: "invalid_public_key", request_id: req.id });
  }
  if (typeof signatureBase64 !== "string" || signatureBase64.length < 10 || signatureBase64.length > 200) {
    return res.status(400).json({ error: "invalid_signature", request_id: req.id });
  }
  try {
    await pool.query(
      `INSERT INTO signed_prekeys (user_id, key_id, public_key_base64, signature_base64, uploaded_at)
       VALUES ($1::uuid, $2, $3, $4, NOW())
       ON CONFLICT (user_id, key_id) DO UPDATE
       SET public_key_base64 = EXCLUDED.public_key_base64,
           signature_base64 = EXCLUDED.signature_base64,
           uploaded_at = NOW()`,
      [userId, keyId, publicKeyBase64, signatureBase64]
    );
    return res.json({ ok: true, key_id: keyId });
  } catch (e) {
    log("error", "put_signed_prekey_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// POST /keys/:userId/one-time-prekeys — upload batch of one-time prekeys
app.post("/keys/:userId/one-time-prekeys", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const keys = req.body?.keys;
  const replaceExisting = req.body?.replace_existing === true;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 100) {
    return res.status(400).json({ error: "invalid_keys_array", request_id: req.id });
  }
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      if (replaceExisting) {
        await client.query(`DELETE FROM one_time_prekeys WHERE user_id = $1::uuid`, [userId]);
        // Pending initial X3DH messages depend on the previous OTP set and cannot be
        // decrypted once the device repairs/replaces its local OTP inventory.
        await client.query(`DELETE FROM initial_x3dh_messages WHERE recipient_id = $1::uuid AND consumed_at IS NULL`, [userId]);
      }
      for (const k of keys) {
        const kid = Number(k.key_id);
        if (!Number.isInteger(kid) || kid < 0 || !validatePublicKeyBase64(k.public_key_base64)) continue;
        await client.query(
          `INSERT INTO one_time_prekeys (user_id, key_id, public_key_base64, uploaded_at)
           VALUES ($1::uuid, $2, $3, NOW())
           ON CONFLICT (user_id, key_id) DO NOTHING`,
          [userId, kid, k.public_key_base64]
        );
      }
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
    return res.json({ ok: true, uploaded: keys.length, replaced_existing: replaceExisting });
  } catch (e) {
    log("error", "post_one_time_prekeys_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// GET /keys/:userId/bundle — fetch prekey bundle (identity + signed prekey + one OT prekey consumed)
app.get("/keys/:userId/bundle", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    const identityResult = await pool.query(
      `SELECT public_key_base64, key_type, signing_public_key_base64 FROM user_identity_keys WHERE user_id = $1::uuid LIMIT 1`,
      [userId]
    );
    if (identityResult.rowCount === 0) {
      return res.status(404).json({ error: "no_identity_key", request_id: req.id });
    }

    const spkResult = await pool.query(
      `SELECT key_id, public_key_base64, signature_base64
       FROM signed_prekeys WHERE user_id = $1::uuid
       ORDER BY uploaded_at DESC LIMIT 1`,
      [userId]
    );

    // Atomically consume one one-time prekey (DELETE RETURNING)
    const otpResult = await pool.query(
      `DELETE FROM one_time_prekeys
       WHERE id = (
         SELECT id FROM one_time_prekeys
         WHERE user_id = $1::uuid
         ORDER BY key_id ASC LIMIT 1
       )
       RETURNING key_id, public_key_base64`,
      [userId]
    );

    const bundle = {
      identity_key: identityResult.rows[0].public_key_base64,
      identity_key_type: identityResult.rows[0].key_type,
      signing_public_key: identityResult.rows[0].signing_public_key_base64 || null,
    };

    if (spkResult.rowCount > 0) {
      bundle.signed_prekey = {
        key_id: spkResult.rows[0].key_id,
        public_key_base64: spkResult.rows[0].public_key_base64,
        signature_base64: spkResult.rows[0].signature_base64,
      };
    }

    if (otpResult.rowCount > 0) {
      bundle.one_time_prekey = {
        key_id: otpResult.rows[0].key_id,
        public_key_base64: otpResult.rows[0].public_key_base64,
      };
    }

    return res.json(bundle);
  } catch (e) {
    log("error", "get_prekey_bundle_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// GET /keys/:userId/one-time-prekeys/count — check remaining OT prekeys
app.get("/keys/:userId/one-time-prekeys/count", requireApiKey, requireRelaySignature, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT COUNT(*)::int AS count FROM one_time_prekeys WHERE user_id = $1::uuid`,
      [userId]
    );
    return res.json({ count: result.rows[0].count });
  } catch (e) {
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// ─── Pad Batches ────────────────────────────────────────────────────────

app.post("/pad-batches", requireApiKey, requireRelaySignature, async (req, res) => {
  const err = validatePadBatchBody(req.body);
  if (err) {
    return res.status(400).json({ error: err, request_id: req.id });
  }

  const body = req.body;
  const ttlSec = Number.isFinite(Number(body.ttl_seconds))
    ? Number(body.ttl_seconds)
    : PAD_BATCH_DEFAULT_TTL_SEC;
  const expiresAt = new Date(Date.now() + ttlSec * 1000).toISOString();

  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      const token = makePadBatchToken();
      try {
        await pool.query(
          `INSERT INTO pad_batches
          (token, conversation_id, direction, pads_json, owner_user_id, expires_at, created_at, consumed_at, consume_count)
          VALUES ($1, $2::uuid, $3, $4::jsonb, $5::uuid, $6::timestamptz, NOW(), NULL, 0)`,
          [
            token,
            body.conversation_id,
            body.direction,
            JSON.stringify(body.pads),
            body.owner_user_id || null,
            expiresAt,
          ]
        );
        return res.status(201).json({ token, expires_at: expiresAt, request_id: req.id });
      } catch (inner) {
        if (inner && inner.code === "23505") {
          continue;
        }
        throw inner;
      }
    }
    return res.status(500).json({ error: "token_generation_failed", request_id: req.id });
  } catch (e) {
    log("error", "create_pad_batch_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.post("/pad-batches/:token/consume", requireApiKey, requireRelaySignature, async (req, res) => {
  const token = String(req.params.token || "").trim().toUpperCase();
  if (!/^VP-[A-Z0-9]{6}-[A-Z0-9]{2}$/.test(token)) {
    return res.status(400).json({ error: "invalid_token", request_id: req.id });
  }
  const requesterUserId = req.body?.requester_user_id;
  if (requesterUserId && !UUID_RE.test(requesterUserId)) {
    return res.status(400).json({ error: "invalid_requester_user_id", request_id: req.id });
  }
  try {
    await sweepExpiredPadBatches();
    const consume = await pool.query(
      `UPDATE pad_batches
       SET consumed_at = NOW(),
           consume_count = consume_count + 1
       WHERE token = $1
         AND consumed_at IS NULL
         AND expires_at > NOW()
         AND (owner_user_id IS NULL OR owner_user_id = $2::uuid)
       RETURNING token, conversation_id, direction, pads_json, owner_user_id, expires_at`,
      [token, requesterUserId || null]
    );
    if (consume.rowCount === 1) {
      const row = consume.rows[0];
      return res.json({
        token: row.token,
        conversation_id: row.conversation_id,
        direction: row.direction,
        pads: row.pads_json,
        owner_user_id: row.owner_user_id,
        expires_at: row.expires_at,
        request_id: req.id,
      });
    }

    const result = await pool.query(
      `SELECT token, owner_user_id, expires_at, consumed_at
       FROM pad_batches
       WHERE token = $1
       LIMIT 1`,
      [token]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "batch_not_found", request_id: req.id });
    }
    const row = result.rows[0];
    if (row.owner_user_id && !requesterUserId) {
      return res.status(400).json({ error: "requester_user_id_required", request_id: req.id });
    }
    if (row.owner_user_id && requesterUserId && String(row.owner_user_id) !== String(requesterUserId)) {
      return res.status(403).json({ error: "owner_mismatch", request_id: req.id });
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return res.status(410).json({ error: "batch_expired", request_id: req.id });
    }
    if (row.consumed_at) {
      return res.status(410).json({ error: "batch_consumed", request_id: req.id });
    }
    return res.status(409).json({ error: "batch_not_consumable", request_id: req.id });
  } catch (e) {
    log("error", "fetch_pad_batch_db", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.post("/messages", requireApiKey, requireRelaySignature, postMessageLimiter, async (req, res) => {
  const error = validateMessageDTO(req.body || {});
  if (error) {
    return res.status(400).json({ error, request_id: req.id });
  }

  const m = req.body;

  try {
    const susp = await pool.query(
      `SELECT suspended FROM users WHERE user_id = $1::uuid LIMIT 1`,
      [m.sender_id]
    );
    if (susp.rowCount > 0 && susp.rows[0].suspended === true) {
      return res.status(403).json({ error: "sender_suspended", request_id: req.id });
    }
  } catch (e) {
    log("error", "sender_suspend_check", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }

  try {
    const result = await pool.query(
      `INSERT INTO messages
      (message_id, conversation_id, sender_id, recipient_id, pad_id, ciphertext_base64, created_at, received_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (message_id) DO NOTHING
      RETURNING message_id`,
      [
        m.message_id,
        m.conversation_id,
        m.sender_id,
        m.recipient_id,
        m.pad_id,
        m.ciphertext_base64,
        m.created_at,
        new Date().toISOString(),
      ]
    );

    if (result.rowCount === 0) {
      return res.status(200).json({
        status: "duplicate_accepted",
        request_id: req.id,
      });
    }

    void pushGenericNewMessageNotification({
      recipientId: m.recipient_id,
      senderId: m.sender_id,
      conversationId: m.conversation_id,
      messageId: m.message_id,
      kind: "message",
    });

    return res.status(201).json({ status: "stored", request_id: req.id });
  } catch (e) {
    log("error", "post_messages_db", {
      message: e.message,
      request_id: req.id,
    });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.get(
  "/conversations/:conversationId/messages",
  requireApiKey,
  requireRelaySignature,
  getMessagesLimiter,
  async (req, res) => {
  const { conversationId } = req.params;

  if (!UUID_RE.test(conversationId)) {
      return res.status(400).json({
        error: "invalid conversation_id",
        request_id: req.id,
      });
    }

    const sinceRaw = req.query.since;
    const since =
      typeof sinceRaw === "string" && sinceRaw.length > 0
        ? sinceRaw
        : "1970-01-01T00:00:00.000Z";

    const n =
      req.query.limit === undefined ? NaN : Number(req.query.limit);
    const limit = Math.min(
      Math.max(Number.isFinite(n) ? Math.floor(n) : 50, 1),
      200
    );

    const viewerRaw = String(req.query.user_id || "").trim();

    try {
      let sql = `SELECT
        message_id,
        conversation_id,
        sender_id,
        recipient_id,
        pad_id,
        ciphertext_base64,
        created_at,
        delivered_at
       FROM messages
       WHERE conversation_id = $1::uuid
         AND (created_at::timestamptz) > $2::timestamptz`;
      const params = [conversationId, since, limit];
      if (UUID_RE.test(viewerRaw)) {
        sql += ` AND (sender_id = $4::uuid OR recipient_id = $4::uuid)`;
        params.push(viewerRaw);
      }
      sql += ` ORDER BY created_at ASC LIMIT $3`;
      const result = await pool.query(sql, params);

      res.setHeader("Cache-Control", "private, no-store");
      return res.json(result.rows);
    } catch (e) {
      log("error", "get_messages_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

app.delete(
  "/conversations/:conversationId/messages",
  requireApiKey,
  requireRelaySignature,
  async (req, res) => {
    const { conversationId } = req.params;
    if (!UUID_RE.test(conversationId)) {
      return res.status(400).json({ error: "invalid_conversation_id", request_id: req.id });
    }
    const requesterUserId = String(req.query.user_id || "").trim();
    if (!UUID_RE.test(requesterUserId)) {
      return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
    }

    try {
      const result = await pool.query(
        `DELETE FROM messages
         WHERE conversation_id = $1::uuid
           AND (sender_id = $2::uuid OR recipient_id = $2::uuid)`,
        [conversationId, requesterUserId]
      );
      return res.json({
        status: "conversation_messages_deleted",
        deleted_count: result.rowCount || 0,
        request_id: req.id,
      });
    } catch (e) {
      log("error", "delete_conversation_messages_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// Delete a single message — only sender or recipient may delete their copy
app.delete(
  "/messages/:messageId",
  requireApiKey,
  requireRelaySignature,
  async (req, res) => {
    const { messageId } = req.params;
    if (!UUID_RE.test(messageId)) {
      return res.status(400).json({ error: "invalid_message_id", request_id: req.id });
    }
    const requesterUserId = String(req.query.user_id || "").trim();
    if (!UUID_RE.test(requesterUserId)) {
      return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
    }
    try {
      const result = await pool.query(
        `DELETE FROM messages
         WHERE message_id = $1::uuid
           AND (sender_id = $2::uuid OR recipient_id = $2::uuid)`,
        [messageId, requesterUserId]
      );
      if (result.rowCount === 0) {
        return res.status(404).json({ error: "message_not_found", request_id: req.id });
      }
      return res.json({ status: "message_deleted", request_id: req.id });
    } catch (e) {
      log("error", "delete_message_db", { message: e.message, request_id: req.id });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

app.get(
  "/messages/inbox/:recipientId",
  requireApiKey,
  requireRelaySignature,
  getMessagesLimiter,
  async (req, res) => {
    const { recipientId } = req.params;
    if (!UUID_RE.test(recipientId)) {
      return res.status(400).json({
        error: "invalid recipient_id",
        request_id: req.id,
      });
    }

    const sinceRaw = req.query.since;
    const since =
      typeof sinceRaw === "string" && sinceRaw.length > 0
        ? sinceRaw
        : "1970-01-01T00:00:00.000Z";

    const n =
      req.query.limit === undefined ? NaN : Number(req.query.limit);
    const limit = Math.min(
      Math.max(Number.isFinite(n) ? Math.floor(n) : 50, 1),
      200
    );

    try {
      const result = await pool.query(
        `SELECT
        message_id,
        conversation_id,
        sender_id,
        recipient_id,
        pad_id,
        ciphertext_base64,
        created_at,
        delivered_at
       FROM messages
       WHERE recipient_id = $1::uuid
         AND (created_at::timestamptz) > $2::timestamptz
       ORDER BY created_at ASC
       LIMIT $3`,
        [recipientId, since, limit]
      );

      res.setHeader("Cache-Control", "private, no-store");
      return res.json(result.rows);
    } catch (e) {
      log("error", "get_inbox_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// POST — сохранить initial message
app.post(
  "/messages/initial-x3dh",
  requireApiKey,
  requireRelaySignature,
  postMessageLimiter,
  async (req, res) => {
    const error = validateInitialX3DHMessageDTO(req.body || {});
    if (error) {
      return res.status(400).json({ error, request_id: req.id });
    }
    const m = req.body;
    try {
      const result = await pool.query(
        `INSERT INTO initial_x3dh_messages
         (message_id, conversation_id, sender_id, recipient_id,
          identity_key, ephemeral_key,
          signed_prekey_id, one_time_prekey_id,
          ciphertext_base64, created_at, received_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (message_id) DO NOTHING
         RETURNING message_id`,
        [
          m.message_id,
          m.conversation_id,
          m.sender_id,
          m.recipient_id,
          m.identity_key,
          m.ephemeral_key,
          m.signed_prekey_id,
          m.one_time_prekey_id || null,
          m.ciphertext_base64,
          m.created_at,
          new Date().toISOString(),
        ]
      );
      if (result.rowCount === 0) {
        return res.status(200).json({
          status: "duplicate_accepted",
          request_id: req.id,
        });
      }
      void pushGenericNewMessageNotification({
        recipientId: m.recipient_id,
        senderId: m.sender_id,
        conversationId: m.conversation_id,
        messageId: m.message_id,
        kind: "initial_x3dh",
      });
      return res.status(201).json({
        status: "stored",
        request_id: req.id,
      });
    } catch (e) {
      log("error", "post_initial_x3dh_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// GET — получить initial messages
app.get(
  "/messages/initial-x3dh",
  requireApiKey,
  requireRelaySignature,
  getMessagesLimiter,
  async (req, res) => {
    const recipientId = String(req.query.recipient_id || "").trim();
    if (!UUID_RE.test(recipientId)) {
      return res.status(400).json({
        error: "invalid_recipient_id",
        request_id: req.id,
      });
    }
    const sinceRaw = req.query.since;
    const since =
      typeof sinceRaw === "string" && sinceRaw.length > 0
        ? sinceRaw
        : "1970-01-01T00:00:00.000Z";
    const n = Number(req.query.limit);
    const limit = Math.min(Math.max(Number.isFinite(n) ? Math.floor(n) : 50, 1), 200);
    try {
      const result = await pool.query(
        `SELECT
          message_id,
          conversation_id,
          sender_id,
          recipient_id,
          identity_key,
          ephemeral_key,
          signed_prekey_id,
          one_time_prekey_id,
          ciphertext_base64,
          created_at
         FROM initial_x3dh_messages
         WHERE recipient_id = $1::uuid
           AND consumed_at IS NULL
           AND created_at > $2::timestamptz
         ORDER BY created_at ASC
         LIMIT $3`,
        [recipientId, since, limit]
      );
      res.setHeader("Cache-Control", "private, no-store");
      return res.json(result.rows);
    } catch (e) {
      log("error", "get_initial_x3dh_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// DELETE — пометить как consumed
app.delete(
  "/messages/initial-x3dh/:messageId",
  requireApiKey,
  requireRelaySignature,
  async (req, res) => {
    const { messageId } = req.params;
    const userId = String(req.query.user_id || "").trim();
    if (!UUID_RE.test(messageId)) {
      return res.status(400).json({ error: "invalid_message_id", request_id: req.id });
    }
    if (!UUID_RE.test(userId)) {
      return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
    }
    try {
      const result = await pool.query(
        `UPDATE initial_x3dh_messages
         SET consumed_at = NOW()
         WHERE message_id = $1::uuid
           AND recipient_id = $2::uuid
           AND consumed_at IS NULL
         RETURNING message_id`,
        [messageId, userId]
      );
      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "message_not_found_or_already_consumed",
          request_id: req.id,
        });
      }
      return res.json({
        status: "consumed",
        request_id: req.id,
      });
    } catch (e) {
      log("error", "delete_initial_x3dh_db", {
        message: e.message,
        request_id: req.id,
      });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// POST /messages/:messageId/ack — recipient confirms delivery
app.post(
  "/messages/:messageId/ack",
  requireApiKey,
  requireRelaySignature,
  async (req, res) => {
    const { messageId } = req.params;
    if (!UUID_RE.test(messageId)) {
      return res.status(400).json({ error: "invalid_message_id", request_id: req.id });
    }
    const recipientId = String(req.body?.recipient_id || "").trim();
    if (!UUID_RE.test(recipientId)) {
      return res.status(400).json({ error: "invalid_recipient_id", request_id: req.id });
    }
    try {
      const result = await pool.query(
        `UPDATE messages
         SET delivered_at = NOW()
         WHERE message_id = $1::uuid
           AND recipient_id = $2::uuid
           AND delivered_at IS NULL
         RETURNING message_id, delivered_at`,
        [messageId, recipientId]
      );
      if (result.rowCount === 0) {
        // Either not found, wrong recipient, or already acked — all fine
        return res.json({ status: "already_acked", request_id: req.id });
      }
      return res.json({
        status: "acked",
        delivered_at: result.rows[0].delivered_at,
        request_id: req.id,
      });
    } catch (e) {
      log("error", "ack_message_db", { message: e.message, request_id: req.id });
      return res.status(500).json({ error: "db_error", request_id: req.id });
    }
  }
);

// --- Admin (aggregate metrics only; requires RELAY_ADMIN_TOKEN) ---
app.get("/admin/summary", requireRelayAdmin, async (req, res) => {
  try {
    const users = await pool.query(`SELECT COUNT(*)::int AS c FROM users`);
    const msgs = await pool.query(`SELECT COUNT(*)::int AS c FROM messages`);
    const suspended = await pool.query(
      `SELECT COUNT(*)::int AS c FROM users WHERE suspended = true`
    );
    return res.json({
      request_id: req.id,
      users: users.rows[0]?.c ?? 0,
      messages: msgs.rows[0]?.c ?? 0,
      suspended_users: suspended.rows[0]?.c ?? 0,
    });
  } catch (e) {
    log("error", "admin_summary", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

app.post("/admin/users/:userId/suspend", requireRelayAdmin, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const suspended = Boolean(req.body?.suspended);
  try {
    await pool.query(`UPDATE users SET suspended = $2 WHERE user_id = $1::uuid`, [userId, suspended]);
    return res.json({ request_id: req.id, user_id: userId, suspended });
  } catch (e) {
    log("error", "admin_suspend", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "not_found", request_id: req.id });
});

// Error handler
app.use((err, req, res, _next) => {
  if (err && (err.status === 413 || err.type === "entity.too.large")) {
    log("warn", "payload_too_large", { message: err.message, request_id: req.id });
    if (!res.headersSent) {
      return res.status(413).json({ error: "payload_too_large", request_id: req.id });
    }
    return;
  }
  log("error", "unhandled", { message: err.message, request_id: req.id });
  if (!res.headersSent) {
    res.status(500).json({ error: "internal_error", request_id: req.id });
  }
});

// --- Startup & graceful shutdown ---

if (!DATABASE_URL) {
  log("error", "config", { message: "DATABASE_URL is not set" });
  process.exit(1);
}

let server;

async function verifySchemaOrThrow() {
  const requiredColumns = [
    "message_id",
    "conversation_id",
    "sender_id",
    "recipient_id",
    "pad_id",
    "ciphertext_base64",
    "created_at",
    "received_at",
  ];
  const result = await pool.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'messages'`
  );
  const present = new Set(result.rows.map((r) => r.column_name));
  const missing = requiredColumns.filter((c) => !present.has(c));
  if (missing.length > 0) {
    throw new Error(`messages schema missing columns: ${missing.join(",")}`);
  }
}

async function ensureUsersTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS users (
      user_id UUID PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)`
  );
}

async function ensureUsersOptionalColumns() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_b64 TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_address TEXT`);
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT false`
  );
}

async function ensureBadgesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS user_badges (
      user_id UUID PRIMARY KEY,
      badge_type TEXT NOT NULL CHECK (badge_type IN ('official', 'verified', 'diamond')),
      granted_by TEXT NOT NULL DEFAULT 'admin',
      granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
}

/** Existing deployments may still have the two-value CHECK; widen to include diamond. */
async function migrateBadgesConstraintForDiamond() {
  try {
    const r = await pool.query(
      `SELECT c.conname, pg_get_constraintdef(c.oid) AS def
       FROM pg_constraint c
       JOIN pg_class t ON c.conrelid = t.oid
       WHERE t.relname = 'user_badges' AND c.contype = 'c'`
    );
    for (const row of r.rows) {
      if (String(row.def).includes("badge_type")) {
        const safe = String(row.conname).replace(/"/g, "");
        await pool.query(`ALTER TABLE user_badges DROP CONSTRAINT "${safe}"`);
      }
    }
  } catch (e) {
    log("warn", "badges_drop_constraint", { message: e.message });
  }
  try {
    await pool.query(
      `ALTER TABLE user_badges ADD CONSTRAINT user_badges_badge_type_check CHECK (badge_type IN ('official', 'verified', 'diamond'))`
    );
  } catch (e) {
    if (e.code === "42710") return;
    log("warn", "badges_add_constraint_diamond", { message: e.message });
  }
}

async function ensurePadBatchesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS pad_batches (
      token TEXT PRIMARY KEY,
      conversation_id UUID NOT NULL,
      direction TEXT NOT NULL,
      pads_json JSONB NOT NULL,
      owner_user_id UUID,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      consumed_at TIMESTAMPTZ,
      consume_count INTEGER NOT NULL DEFAULT 0
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_pad_batches_expires_at ON pad_batches (expires_at)`
  );
  await pool.query(
    `ALTER TABLE pad_batches
     ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ`
  );
  await pool.query(
    `ALTER TABLE pad_batches
     ADD COLUMN IF NOT EXISTS consume_count INTEGER NOT NULL DEFAULT 0`
  );
}

async function ensureIdentityKeysTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS user_identity_keys (
      user_id UUID PRIMARY KEY,
      key_type TEXT NOT NULL,
      public_key_base64 TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_identity_keys_updated_at ON user_identity_keys (updated_at)`
  );
  await pool.query(
    `ALTER TABLE user_identity_keys ADD COLUMN IF NOT EXISTS signing_public_key_base64 TEXT`
  ).catch(() => {});
}

async function ensurePrekeysTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS signed_prekeys (
      user_id UUID NOT NULL,
      key_id INTEGER NOT NULL,
      public_key_base64 TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, key_id)
    )`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS one_time_prekeys (
      id SERIAL PRIMARY KEY,
      user_id UUID NOT NULL,
      key_id INTEGER NOT NULL,
      public_key_base64 TEXT NOT NULL,
      uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, key_id)
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_otp_prekeys_user ON one_time_prekeys (user_id)`
  );
}

async function ensureMessagesDeliveredAt() {
  await pool.query(
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ`
  );
}

async function ensurePushDevicesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS user_push_tokens (
      user_id UUID NOT NULL,
      device_token TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'apns',
      bundle_id TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, device_token, platform)
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_push_tokens_user ON user_push_tokens (user_id, updated_at DESC)`
  );
}

async function ensureInitialX3DHMessagesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS initial_x3dh_messages (
      message_id UUID PRIMARY KEY,
      conversation_id UUID NOT NULL,
      sender_id UUID NOT NULL,
      recipient_id UUID NOT NULL,
      identity_key TEXT NOT NULL,
      ephemeral_key TEXT NOT NULL,
      signed_prekey_id INTEGER NOT NULL,
      one_time_prekey_id INTEGER,
      ciphertext_base64 TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      consumed_at TIMESTAMPTZ
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_initial_x3dh_recipient_created
     ON initial_x3dh_messages (recipient_id, created_at)`
  );
}

async function ensureAuthChallengesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS auth_challenges (
      challenge_id TEXT PRIMARY KEY,
      user_id UUID NOT NULL,
      origin TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      client_state TEXT,
      icons_json JSONB NOT NULL,
      correct_icon TEXT NOT NULL,
      selected_icon TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_at TIMESTAMPTZ,
      resolved_at TIMESTAMPTZ
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_auth_challenges_user_expires
     ON auth_challenges (user_id, expires_at DESC)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_auth_challenges_status_expires
     ON auth_challenges (status, expires_at DESC)`
  );
}

async function ensureAuthCodesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS auth_codes (
      code TEXT PRIMARY KEY,
      challenge_id TEXT NOT NULL REFERENCES auth_challenges(challenge_id) ON DELETE CASCADE,
      user_id UUID NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      consumed_at TIMESTAMPTZ
    )`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_auth_codes_challenge
     ON auth_codes (challenge_id, expires_at DESC)`
  );
}

// ─── WebSocket signaling for encrypted calls ───────────────────────────
const WebSocket = require("ws");

const wsClients = new Map(); // userId (string) -> Set<WebSocket>

const WS_MAX_BINARY_FRAME = 4096;
const WS_BACKPRESSURE_LIMIT = 1_000_000; // bytes
const WS_HMAC_WINDOW_SEC = RELAY_HMAC_WINDOW_SEC || 300;
const WS_MSG_RATE_WINDOW_MS = 1000;
const WS_MSG_RATE_MAX = 60; // max signaling messages per window
const WS_AUDIO_RATE_WINDOW_MS = 1000;
const WS_AUDIO_RATE_MAX = 80; // max audio frames per second (~50 expected)

// Replay nonce cache: nonce -> expiry timestamp
const wsReplayNonces = new Map();
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const [nonce, expiry] of wsReplayNonces) {
    if (expiry < now) wsReplayNonces.delete(nonce);
  }
}, 60_000).unref();

// ── WS HMAC authentication ──

function verifyWsHmac(userId, timestamp, nonce, signature) {
  if (!RELAY_HMAC_SECRET) return true; // auth disabled
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) return false;
  if (typeof signature !== "string" || signature.length === 0) return false;
  if (typeof nonce !== "string" || nonce.length === 0) return false;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > WS_HMAC_WINDOW_SEC) return false;

  const nonceKey = `${userId}:${nonce}`;
  if (wsReplayNonces.has(nonceKey)) return false;
  wsReplayNonces.set(nonceKey, now + WS_HMAC_WINDOW_SEC + 60);

  const canonical = `ws.register.${userId}.${timestamp}.${nonce}`;
  const expected = crypto.createHmac("sha256", RELAY_HMAC_SECRET).update(canonical).digest("hex");
  return timingSafeEqualHex(expected, signature);
}

function verifyWsMessageHmac(userId, msg) {
  if (!RELAY_HMAC_SECRET) return true;
  const { _ts, _nonce, _sig } = msg;
  if (typeof _ts !== "number" || typeof _nonce !== "string" || typeof _sig !== "string") return false;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - _ts) > WS_HMAC_WINDOW_SEC) return false;

  const nonceKey = `${userId}:${_nonce}`;
  if (wsReplayNonces.has(nonceKey)) return false;
  wsReplayNonces.set(nonceKey, now + WS_HMAC_WINDOW_SEC + 60);

  const signable = { ...msg };
  delete signable._ts;
  delete signable._nonce;
  delete signable._sig;
  const body = JSON.stringify(signable, Object.keys(signable).sort());
  const canonical = `ws.msg.${userId}.${_ts}.${_nonce}.${body}`;
  const expected = crypto.createHmac("sha256", RELAY_HMAC_SECRET).update(canonical).digest("hex");
  return timingSafeEqualHex(expected, _sig);
}

// ── Conversation ACL: verify both users share a conversation ──

async function verifyConversationAccess(userId, targetUserId, conversationId) {
  if (!conversationId) return false;
  try {
    const result = await pool.query(
      `SELECT 1 FROM messages
       WHERE conversation_id = $1
         AND ((sender_id = $2 AND recipient_id = $3) OR (sender_id = $3 AND recipient_id = $2))
       LIMIT 1`,
      [conversationId, userId, targetUserId]
    );
    if (result.rows.length > 0) return true;

    // Also check identity keys: both users must have published keys
    const keys = await pool.query(
      `SELECT user_id FROM user_identity_keys WHERE user_id IN ($1, $2)`,
      [userId, targetUserId]
    );
    return keys.rows.length === 2;
  } catch {
    return false;
  }
}

// ── Rate limiter per connection ──

class WsRateLimiter {
  constructor(windowMs, maxHits) {
    this.windowMs = windowMs;
    this.maxHits = maxHits;
    this.hits = 0;
    this.windowStart = Date.now();
  }
  check() {
    const now = Date.now();
    if (now - this.windowStart > this.windowMs) {
      this.hits = 0;
      this.windowStart = now;
    }
    this.hits++;
    return this.hits <= this.maxHits;
  }
}

// ── Core WS functions ──

function wsRegister(userId, ws) {
  if (!wsClients.has(userId)) wsClients.set(userId, new Set());
  wsClients.get(userId).add(ws);
  log("info", "ws_register", { userId, total: wsClients.get(userId).size });
}

function wsUnregister(userId, ws) {
  const set = wsClients.get(userId);
  if (set) {
    set.delete(ws);
    if (set.size === 0) wsClients.delete(userId);
  }
}

function wsSendTo(targetUserId, payload) {
  const set = wsClients.get(targetUserId);
  if (!set || set.size === 0) return false;
  const raw = Buffer.isBuffer(payload) ? payload : (typeof payload === "string" ? payload : JSON.stringify(payload));
  for (const ws of set) {
    if (ws.readyState !== WebSocket.OPEN) continue;
    // Backpressure: terminate slow consumers
    if (ws.bufferedAmount > WS_BACKPRESSURE_LIMIT) {
      log("warn", "ws_backpressure_kill", { target: targetUserId, buffered: ws.bufferedAmount });
      ws.terminate();
      continue;
    }
    ws.send(raw);
  }
  return true;
}

function stripAuthFields(obj) {
  const clean = { ...obj };
  delete clean._ts;
  delete clean._nonce;
  delete clean._sig;
  return clean;
}

function handleSignaling(ws, msg, fromUserId) {
  const { type, callId, targetUserId } = msg;
  if (!targetUserId || !fromUserId) return;
  const forwarded = stripAuthFields(msg);

  switch (type) {
    case "call_offer":
    case "call_answer":
    case "call_decline":
    case "call_end":
    case "call_ice": {
      const delivered = wsSendTo(targetUserId, forwarded);
      if (type === "call_offer" && !delivered) {
        const reject = JSON.stringify({
          type: "call_unavailable",
          callId,
          targetUserId,
          reason: "offline",
        });
        if (ws.readyState === WebSocket.OPEN) ws.send(reject);
      }
      break;
    }
    default:
      break;
  }
}

function setupWebSocket(httpServer) {
  const wss = new WebSocket.Server({ server: httpServer, path: "/ws", maxPayload: 8192 });

  wss.on("connection", (ws, req) => {
    let registeredUserId = null;
    let callPeerId = null;
    const msgLimiter = new WsRateLimiter(WS_MSG_RATE_WINDOW_MS, WS_MSG_RATE_MAX);
    const audioLimiter = new WsRateLimiter(WS_AUDIO_RATE_WINDOW_MS, WS_AUDIO_RATE_MAX);

    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (data, isBinary) => {
      // ── Binary audio frames ──
      if (isBinary || (Buffer.isBuffer(data) && data.length > 0 && data[0] !== 0x7b)) {
        if (!registeredUserId || !callPeerId) return;
        if (data.length > WS_MAX_BINARY_FRAME) return; // size cap
        if (!audioLimiter.check()) return; // rate limit
        wsSendTo(callPeerId, data);
        return;
      }

      // ── Text signaling ──
      if (!msgLimiter.check()) {
        ws.send(JSON.stringify({ type: "error", message: "rate_limited" }));
        return;
      }

      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }

      // ── Register (with HMAC auth) ──
      if (msg.type === "register" && typeof msg.userId === "string" && msg.userId.length > 0) {
        if (!verifyWsHmac(msg.userId, msg.timestamp, msg.nonce, msg.signature)) {
          ws.send(JSON.stringify({ type: "error", message: "auth_failed" }));
          ws.close(4001, "auth_failed");
          return;
        }
        if (registeredUserId) wsUnregister(registeredUserId, ws);
        registeredUserId = msg.userId;
        wsRegister(registeredUserId, ws);
        ws.send(JSON.stringify({ type: "registered", userId: registeredUserId }));
        return;
      }

      if (!registeredUserId) {
        ws.send(JSON.stringify({ type: "error", message: "register first" }));
        return;
      }

      // ── Verify per-message HMAC ──
      if (!verifyWsMessageHmac(registeredUserId, msg)) {
        ws.send(JSON.stringify({ type: "error", message: "sig_failed" }));
        return;
      }

      // ── Conversation ACL for call_offer ──
      if (msg.type === "call_offer") {
        const convId = msg.conversationId;
        const target = msg.targetUserId;
        verifyConversationAccess(registeredUserId, target, convId).then((allowed) => {
          if (!allowed) {
            ws.send(JSON.stringify({ type: "error", message: "no_conversation" }));
            return;
          }
          callPeerId = target || null;
          handleSignaling(ws, { ...msg, fromUserId: registeredUserId }, registeredUserId);
        });
        return;
      }

      // ── ACL for call_answer ──
      if (msg.type === "call_answer") {
        const target = msg.targetUserId;
        const convId = msg.conversationId;
        verifyConversationAccess(registeredUserId, target, convId).then((allowed) => {
          if (!allowed) {
            ws.send(JSON.stringify({ type: "error", message: "no_conversation" }));
            return;
          }
          callPeerId = target || null;
          handleSignaling(ws, { ...msg, fromUserId: registeredUserId }, registeredUserId);
        });
        return;
      }

      if (msg.type === "call_end" || msg.type === "call_decline") {
        callPeerId = null;
      }

      handleSignaling(ws, { ...msg, fromUserId: registeredUserId }, registeredUserId);
    });

    ws.on("close", () => {
      if (registeredUserId) wsUnregister(registeredUserId, ws);
    });

    ws.on("error", () => {
      if (registeredUserId) wsUnregister(registeredUserId, ws);
    });
  });

  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30_000);

  wss.on("close", () => clearInterval(heartbeat));
  log("info", "ws_ready", { path: "/ws" });
}

async function bootstrap() {
  await verifySchemaOrThrow();
  await ensureUsersTable();
  await ensureUsersOptionalColumns();
  await ensureBadgesTable();
  await migrateBadgesConstraintForDiamond();
  await ensurePadBatchesTable();
  await ensureIdentityKeysTable();
  await ensurePrekeysTable();
  await ensureInitialX3DHMessagesTable();
  await ensureAuthChallengesTable();
  await ensureAuthCodesTable();
  await ensureMessagesDeliveredAt();
  await ensurePushDevicesTable();
  await sweepExpiredPadBatches();
  await sweepExpiredAuthArtifacts();
  setInterval(sweepExpiredPadBatches, PAD_BATCH_SWEEP_INTERVAL_SEC * 1000).unref();
  setInterval(sweepExpiredAuthArtifacts, PAD_BATCH_SWEEP_INTERVAL_SEC * 1000).unref();
  server = app.listen(PORT, () => {
    log("info", "listen", {
      port: PORT,
      api_key_required: Boolean(RELAY_API_KEY),
      hmac_required: Boolean(RELAY_HMAC_SECRET),
      apns_enabled: hasApnsConfig(),
      cors_origins: RELAY_ALLOWED_ORIGINS?.length ?? "any",
    });
  });
  setupWebSocket(server);
}

bootstrap().catch((e) => {
  log("error", "bootstrap_failed", { message: e.message });
  process.exit(1);
});

function shutdown(signal) {
  log("info", "shutdown", { signal });
  if (!server) {
    pool.end(() => process.exit(0));
    return;
  }
  server.close(() => {
    pool.end(() => {
      process.exit(0);
    });
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
