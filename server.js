const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const SECRET = "LixVip2024_SieuBaoMat_DoiDiNhe";
const DB_FILE = "./db.json";

// Tài khoản admin
const ADMIN = {
  username: "admin",
  passwordHash: bcrypt.hashSync("admin123", 10)
};

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ keys: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}
function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function auth(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Chưa đăng nhập" });
  try {
    jwt.verify(token.replace("Bearer ", ""), SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token sai" });
  }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN.username || !bcrypt.compareSync(password, ADMIN.passwordHash)) {
    return res.status(401).json({ error: "Sai tài khoản" });
  }
  const token = jwt.sign({ username }, SECRET, { expiresIn: "7d" });
  res.json({ token });
});

function durationToMs(type) {
  switch (type) {
    case "1h": return 60 * 60 * 1000;
    case "1d": return 24 * 60 * 60 * 1000;
    case "1w": return 7 * 24 * 60 * 60 * 1000;
    case "1m": return 30 * 24 * 60 * 60 * 1000;
    case "1y": return 365 * 24 * 60 * 60 * 1000;
    case "forever": return null;
    default: return null;
  }
}

function randomKey(len = 20) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++)
    out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

app.post("/api/create-key", auth, (req, res) => {
  const { duration } = req.body;
  const db = loadDB();
  const key = randomKey();
  const ms = durationToMs(duration);

  const item = {
    key,
    duration,
    createdAt: Date.now(),
    expiresAt: ms ? Date.now() + ms : null,
    uid: null
  };
  db.keys.push(item);
  saveDB(db);
  res.json({ success: true, key, item });
});

app.delete("/api/delete-key/:key", auth, (req, res) => {
  const db = loadDB();
  const before = db.keys.length;
  db.keys = db.keys.filter(k => k.key !== req.params.key);
  saveDB(db);
  res.json({ success: true, deleted: before - db.keys.length });
});

app.get("/api/keys", auth, (req, res) => {
  const db = loadDB();
  res.json({ keys: db.keys });
});

app.post("/api/check-key", (req, res) => {
  const { key, uid } = req.body;
  const db = loadDB();
  const item = db.keys.find(k => k.key === key);

  if (!item) return res.json({ valid: false, reason: "Key không tồn tại" });
  if (item.expiresAt && Date.now() > item.expiresAt)
    return res.json({ valid: false, reason: "Key đã hết hạn" });

  if (!item.uid) {
    item.uid = uid;
    saveDB(db);
    return res.json({ valid: true, msg: "Kích hoạt thành công" });
  }

  if (item.uid !== uid)
    return res.json({ valid: false, reason: "Key đã gắn thiết bị khác" });

  res.json({ valid: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server chạy port " + PORT));
