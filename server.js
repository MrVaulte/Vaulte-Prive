const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const MIN_CIPHERTEXT_BYTES = 1;
const MAX_CIPHERTEXT_BYTES = 256 * 1024;

// 🔌 Подключение к Supabase (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// --- VALIDATION ---

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const BASE64_RE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function isIsoDate(value) {
  if (typeof value !== "string") return false;
  return !Number.isNaN(Date.parse(value));
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
    if (!(key in body)) {
      return `missing field: ${key}`;
    }
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

  if (!BASE64_RE.test(body.ciphertext_base64)) {
    return "invalid base64";
  }

  if (!isIsoDate(body.created_at)) {
    return "invalid date";
  }

  const opaqueErr = validateOpaqueCipherBase64(body.ciphertext_base64);
  if (opaqueErr) {
    return opaqueErr;
  }

  return null;
}

/**
 * Relay never decrypts. We only reject payloads that look like raw UTF-8 text
 * (accidental plaintext). Real OTP/XOR or AEAD ciphertext should look high-entropy.
 */
function validateOpaqueCipherBase64(b64) {
  let buf;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    return "invalid base64 decode";
  }
  if (buf.length < MIN_CIPHERTEXT_BYTES) {
    return "ciphertext_too_short";
  }
  if (buf.length > MAX_CIPHERTEXT_BYTES) {
    return "ciphertext_too_large";
  }
  if (buf.length >= 24) {
    let printable = 0;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if (b >= 0x20 && b <= 0x7e) {
        printable++;
      }
    }
    const ratio = printable / buf.length;
    if (ratio > 0.97) {
      return "rejected_plaintext_like_payload";
    }
  }
  return null;
}

// --- ROUTES ---

app.get("/", (_req, res) => {
  res.send("Vaulte relay running");
});

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

// 📥 SAVE MESSAGE
app.post("/messages", async (req, res) => {
  const error = validateMessageDTO(req.body || {});
  if (error) {
    return res.status(400).json({ error });
  }

  const m = req.body;

  try {
    // проверка дубля
    const existing = await pool.query(
      "SELECT 1 FROM messages WHERE message_id = $1",
      [m.message_id]
    );

    if (existing.rowCount > 0) {
      return res.json({ status: "duplicate_accepted" });
    }

    await pool.query(
      `INSERT INTO messages
      (message_id, conversation_id, sender_id, recipient_id, pad_id, ciphertext_base64, created_at, received_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        m.message_id,
        m.conversation_id,
        m.sender_id,
        m.recipient_id,
        m.pad_id,
        m.ciphertext_base64,
        m.created_at,
        new Date().toISOString()
      ]
    );

    res.status(201).json({ status: "stored" });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "db_error" });
  }
});

// 📤 GET MESSAGES
app.get("/conversations/:conversationId/messages", async (req, res) => {
  const { conversationId } = req.params;

  if (!UUID_RE.test(conversationId)) {
    return res.status(400).json({ error: "invalid conversation_id" });
  }

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
       WHERE conversation_id = $1
       ORDER BY created_at ASC`,
      [conversationId]
    );

    res.json(result.rows);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "db_error" });
  }
});

// --- START ---

app.listen(PORT, () => {
  console.log(`Vaulte relay listening on :${PORT}`);
});