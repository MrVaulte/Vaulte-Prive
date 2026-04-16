/**
 * Vaulte Privé relay — production-oriented opaque message store.
 * Never decrypts ciphertext; validates shape + anti-plaintext heuristic only.
 */

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const MIN_CIPHERTEXT_BYTES = 1;
const MAX_CIPHERTEXT_BYTES = 256 * 1024;
const PAD_BATCH_DEFAULT_TTL_SEC = Number(process.env.PAD_BATCH_DEFAULT_TTL_SEC || 86400);
const PAD_BATCH_MAX_PADS = Number(process.env.PAD_BATCH_MAX_PADS || 100);
const PAD_BATCH_SWEEP_INTERVAL_SEC = Number(process.env.PAD_BATCH_SWEEP_INTERVAL_SEC || 3600);

const DATABASE_URL = process.env.DATABASE_URL;
const RELAY_API_KEY = process.env.RELAY_API_KEY?.trim();
const RELAY_HMAC_SECRET = process.env.RELAY_HMAC_SECRET?.trim();
const RELAY_HMAC_WINDOW_SEC = Number(process.env.RELAY_HMAC_WINDOW_SEC || 300);
const RELAY_ADMIN_USERNAMES = (process.env.RELAY_ADMIN_USERNAMES || "vaulte")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const RELAY_ALLOWED_ORIGINS = process.env.RELAY_ALLOWED_ORIGINS?.split(",")
  .map((s) => s.trim())
  .filter(Boolean);

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
    limit: "1mb",
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

// --- VALIDATION ---

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const USERNAME_RE = /^[a-z0-9_]{3,24}$/;
const KEY_TYPE_X25519 = "x25519";

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

async function sweepExpiredPadBatches() {
  try {
    await pool.query(`DELETE FROM pad_batches WHERE expires_at < NOW()`);
  } catch (e) {
    log("error", "sweep_pad_batches_failed", { message: e.message });
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

app.get("/users/resolve", requireApiKey, requireRelaySignature, async (req, res) => {
  const username = normalizeUsername(req.query.username);
  if (!username) {
    return res.status(400).json({ error: "invalid_username", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, username, display_name, avatar_b64, updated_at
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
      `SELECT user_id, username, display_name, avatar_b64, updated_at
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
      `SELECT user_id, username, display_name, avatar_b64, updated_at
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
  const normalized = normalizeUsername(req.body?.username);
  if (!normalized) {
    return res.status(400).json({ error: "invalid_username", request_id: req.id });
  }

  // Block non-admins from taking a reserved admin username
  if (RELAY_ADMIN_USERNAMES.includes(normalized.toLowerCase())) {
    const existing = await pool.query(
      `SELECT user_id FROM users WHERE LOWER(username) = $1 LIMIT 1`,
      [normalized.toLowerCase()]
    );
    if (existing.rowCount > 0 && existing.rows[0].user_id !== userId) {
      return res.status(403).json({ error: "admin_username_reserved", request_id: req.id });
    }
  }

  // Block renaming an admin account to a different username
  if (await isProtectedAdmin(userId)) {
    const current = await pool.query(
      `SELECT username FROM users WHERE user_id = $1::uuid LIMIT 1`,
      [userId]
    );
    if (current.rowCount > 0 && current.rows[0].username?.toLowerCase() !== normalized.toLowerCase()) {
      return res.status(403).json({ error: "admin_username_locked", request_id: req.id });
    }
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
    const MAX_AVATAR_B64 = 600_000;
    if (trimmed.length > MAX_AVATAR_B64) {
      return res.status(400).json({ error: "avatar_too_large", request_id: req.id });
    }
    avatarParam = trimmed.length ? trimmed : null;
  }
  const insertAvatar = avatarInBody ? avatarParam : null;

  try {
    const result = await pool.query(
      `INSERT INTO users (user_id, username, display_name, avatar_b64, updated_at)
       VALUES ($1::uuid, $2, $3, $4, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET username = EXCLUDED.username,
           display_name = COALESCE(EXCLUDED.display_name, users.display_name),
           avatar_b64 = CASE WHEN $5::boolean THEN EXCLUDED.avatar_b64 ELSE users.avatar_b64 END,
           updated_at = NOW()
       RETURNING user_id, username, display_name, avatar_b64, updated_at`,
      [userId, normalized, displayName, insertAvatar, avatarInBody]
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
  if (await isProtectedAdmin(userId)) {
    log("warn", "hard_reset_blocked_admin", { user_id: userId, request_id: req.id });
    return res.status(403).json({ error: "admin_account_protected", request_id: req.id });
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

// --- Admin account protection: prevents deletion of admin accounts ---
async function isProtectedAdmin(userId) {
  try {
    const result = await pool.query(
      `SELECT username FROM users WHERE user_id = $1::uuid LIMIT 1`,
      [userId]
    );
    if (result.rowCount === 0) return false;
    return RELAY_ADMIN_USERNAMES.includes(result.rows[0].username?.toLowerCase());
  } catch {
    return false;
  }
}

// --- Admin middleware: checks X-Admin-User-Id header against allowed usernames ---
async function requireAdmin(req, res, next) {
  const adminUserId = req.headers["x-admin-user-id"]?.trim();
  if (!adminUserId || !UUID_RE.test(adminUserId)) {
    return res.status(403).json({ error: "forbidden", request_id: req.id });
  }
  try {
    const result = await pool.query(
      `SELECT username FROM users WHERE user_id = $1::uuid LIMIT 1`,
      [adminUserId]
    );
    if (result.rowCount === 0) {
      return res.status(403).json({ error: "forbidden", request_id: req.id });
    }
    const username = result.rows[0].username?.toLowerCase();
    if (!RELAY_ADMIN_USERNAMES.includes(username)) {
      return res.status(403).json({ error: "forbidden", request_id: req.id });
    }
    req.adminUserId = adminUserId;
    req.adminUsername = username;
    next();
  } catch (e) {
    log("error", "admin_check_failed", { message: e.message, request_id: req.id });
    return res.status(500).json({ error: "db_error", request_id: req.id });
  }
}

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
// badge_type: "official" (admin-granted, gold) or "verified" (purchased, blue)
app.put("/badges/:userId", requireApiKey, requireRelaySignature, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  const badgeType = req.body?.badge_type;
  if (!["official", "verified"].includes(badgeType)) {
    return res.status(400).json({ error: "invalid_badge_type", valid: ["official", "verified"], request_id: req.id });
  }
  const grantedBy = req.adminUsername || "admin";
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

// DELETE /badges/:userId — admin revokes a badge
app.delete("/badges/:userId", requireApiKey, requireRelaySignature, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: "invalid_user_id", request_id: req.id });
  }
  if (await isProtectedAdmin(userId)) {
    return res.status(403).json({ error: "admin_badge_protected", request_id: req.id });
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
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 100) {
    return res.status(400).json({ error: "invalid_keys_array", request_id: req.id });
  }
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
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
    return res.json({ ok: true, uploaded: keys.length });
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

    try {
      const result = await pool.query(
        `SELECT
        message_id,
        conversation_id,
        sender_id,
        recipient_id,
        pad_id,
        ciphertext_base64,
        created_at
       FROM messages
       WHERE conversation_id = $1::uuid
         AND (created_at::timestamptz) > $2::timestamptz
       ORDER BY created_at ASC
       LIMIT $3`,
        [conversationId, since, limit]
      );

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
        created_at
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

// 404
app.use((req, res) => {
  res.status(404).json({ error: "not_found", request_id: req.id });
});

// Error handler
app.use((err, req, res, _next) => {
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
}

async function ensureBadgesTable() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS user_badges (
      user_id UUID PRIMARY KEY,
      badge_type TEXT NOT NULL CHECK (badge_type IN ('official', 'verified')),
      granted_by TEXT NOT NULL DEFAULT 'admin',
      granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
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
  await ensurePadBatchesTable();
  await ensureIdentityKeysTable();
  await ensurePrekeysTable();
  await sweepExpiredPadBatches();
  setInterval(sweepExpiredPadBatches, PAD_BATCH_SWEEP_INTERVAL_SEC * 1000).unref();
  server = app.listen(PORT, () => {
    log("info", "listen", {
      port: PORT,
      api_key_required: Boolean(RELAY_API_KEY),
      hmac_required: Boolean(RELAY_HMAC_SECRET),
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
