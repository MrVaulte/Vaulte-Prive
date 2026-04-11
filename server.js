const express = require("express");
const cors = require("cors");

const app = express();

// 🔥 ВАЖНО: Render даёт порт через env
const PORT = process.env.PORT || 3000;

// in-memory storage
let messages = [];

// middleware
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// health check
app.get("/", (req, res) => {
  res.status(200).send("Server is running");
});

// helpers
function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validateMessage(body) {
  const required = [
    "message_id",
    "conversation_id",
    "sender_id",
    "recipient_id",
    "pad_id",
    "ciphertext_base64",
    "created_at",
  ];

  for (const field of required) {
    if (!isNonEmptyString(body[field])) {
      return `Invalid field: ${field}`;
    }
  }

  return null;
}

// POST /messages
app.post("/messages", (req, res) => {
  try {
    const error = validateMessage(req.body);

    if (error) {
      return res.status(400).json({ ok: false, error });
    }

    // защита от дублей
    if (messages.find(m => m.message_id === req.body.message_id)) {
      return res.status(409).json({
        ok: false,
        error: "Duplicate message_id",
      });
    }

    messages.push(req.body);

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// GET /messages
app.get("/messages", (req, res) => {
  res.json({
    ok: true,
    count: messages.length,
    messages,
  });
});

// 🔥 ЭТО КРИТИЧЕСКИЙ ROUTE ДЛЯ ТВОЕГО iOS
app.get("/conversations/:id/messages", (req, res) => {
  const id = req.params.id;

  const filtered = messages.filter(
    m => m.conversation_id === id
  );

  res.json(filtered); // ← именно массив, как ждёт iOS
});

// 404
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Not found" });
});

// старт
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});