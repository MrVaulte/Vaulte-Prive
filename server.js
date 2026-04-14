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

const DATABASE_URL = process.env.DATABASE_URL;
const RELAY_API_KEY = process.env.RELAY_API_KEY?.trim();
const RELAY_HMAC_SECRET = process.env.RELAY_HMAC_SECRET?.trim();
const RELAY_HMAC_WINDOW_SEC = Number(process.env.RELAY_HMAC_WINDOW_SEC || 300);
const RELAY_ALLOWED_ORIGINS = process.env.RELAY_ALLOWED_ORIGINS?.split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Render / reverse proxies
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 1));

// --- PostgreSQL pool (Supabase) ---
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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
  if (token !== RELAY_API_KEY) {
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
  const canonical = `${ts}.${req.method.toUpperCase()}.${req.originalUrl}.${raw}`;
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

  if (buf.length >= 24) {
    let printable = 0;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if (b >= 0x20 && b <= 0x7e) printable++;
    }
    if (printable / buf.length > 0.97) {
      return "rejected_plaintext_like_payload";
    }
  }

  return null;
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
      `SELECT user_id, username, updated_at
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
      `SELECT user_id, username, updated_at
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
      `SELECT user_id, username, updated_at
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
  try {
    const result = await pool.query(
      `INSERT INTO users (user_id, username, updated_at)
       VALUES ($1::uuid, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET username = EXCLUDED.username, updated_at = NOW()
       RETURNING user_id, username, updated_at`,
      [userId, normalized]
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

async function bootstrap() {
  await verifySchemaOrThrow();
  await ensureUsersTable();
  server = app.listen(PORT, () => {
    log("info", "listen", {
      port: PORT,
      api_key_required: Boolean(RELAY_API_KEY),
      hmac_required: Boolean(RELAY_HMAC_SECRET),
      cors_origins: RELAY_ALLOWED_ORIGINS?.length ?? "any",
    });
  });
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
