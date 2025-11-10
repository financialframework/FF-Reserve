// server.js
// FF Reserve - Backend V1
// Core features:
// - Signup (email + phone required)
// - Email + phone verification (both required before activation)
// - Login with HttpOnly session cookie
// - /me for current user
// - Update preferences (locale, theme)
// - Delete account (hard delete)
//
// Dependencies (ensure these are in package.json):
// express, better-sqlite3, cookie-parser, cors, dotenv, argon2, uuid

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import Database from "better-sqlite3";
import argon2 from "argon2";
import { v4 as uuid } from "uuid";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS: allow your frontend origin; for dev you can allow all (tighten later)
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// ---------- DB INITIALIZATION ----------

const db = new Database("ff_reserve.db");
db.pragma("journal_mode = WAL");

// Users table
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  phone           TEXT NOT NULL,
  password_hash   TEXT NOT NULL,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  phone_verified  INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'active'
  locale          TEXT NOT NULL DEFAULT 'en',
  theme           TEXT NOT NULL DEFAULT 'system',  -- 'light' | 'dark' | 'system'
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
`);

// Consent log
db.exec(`
CREATE TABLE IF NOT EXISTS user_consents (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  terms_version   TEXT NOT NULL,
  privacy_version TEXT NOT NULL,
  locale          TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Verification codes
db.exec(`
CREATE TABLE IF NOT EXISTS verification_codes (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  channel         TEXT NOT NULL, -- 'email' | 'phone'
  code_hash       TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER,
  attempts        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Sessions
db.exec(`
CREATE TABLE IF NOT EXISTS sessions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Example user-owned table (extend later for budgets/txns)
db.exec(`
CREATE TABLE IF NOT EXISTS transactions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  date            TEXT NOT NULL,
  description     TEXT NOT NULL,
  amount          REAL NOT NULL,
  currency        TEXT NOT NULL DEFAULT 'USD',
  bucket          TEXT,
  source          TEXT,
  created_at      TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// ---------- HELPERS ----------

const nowMs = () => Date.now();

const getUserByEmail = (email) =>
  db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.toLowerCase());

const getUserById = (id) =>
  db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);

function insertUser({ name, email, phone, passwordHash, locale, theme }) {
  const id = uuid();
  const ts = new Date().toISOString();
  db.prepare(`
    INSERT INTO users (
      id, name, email, phone, password_hash,
      email_verified, phone_verified, status,
      locale, theme, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, 0, 0, 'pending', ?, ?, ?, ?)
  `).run(
    id,
    name,
    email.toLowerCase(),
    phone,
    passwordHash,
    locale || "en",
    theme || "system",
    ts,
    ts
  );
  return getUserById(id);
}

function updateUser(id, patch) {
  const u = getUserById(id);
  if (!u) return null;
  const nu = {
    ...u,
    ...patch,
    email_verified: patch.email_verified !== undefined
      ? (patch.email_verified ? 1 : 0)
      : u.email_verified,
    phone_verified: patch.phone_verified !== undefined
      ? (patch.phone_verified ? 1 : 0)
      : u.phone_verified,
    updated_at: new Date().toISOString()
  };

  db.prepare(`
    UPDATE users
    SET name = ?, email = ?, phone = ?, password_hash = ?,
        email_verified = ?, phone_verified = ?, status = ?,
        locale = ?, theme = ?, updated_at = ?
    WHERE id = ?
  `).run(
    nu.name,
    nu.email,
    nu.phone,
    nu.password_hash,
    nu.email_verified,
    nu.phone_verified,
    nu.status,
    nu.locale,
    nu.theme,
    nu.updated_at,
    id
  );

  return getUserById(id);
}

// Verification codes
async function createVerificationCode(userId, channel) {
  const raw = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
  const hash = await argon2.hash(raw);
  const expiresAt = nowMs() + 15 * 60 * 1000;
  const id = uuid();
  db.prepare(`
    INSERT INTO verification_codes (
      id, user_id, channel, code_hash, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, userId, channel, hash, expiresAt, nowMs());
  return raw;
}

function getLatestCode(userId, channel) {
  return db.prepare(`
    SELECT * FROM verification_codes
    WHERE user_id = ?
      AND channel = ?
      AND used_at IS NULL
      AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 1
  `).get(userId, channel, nowMs());
}

function markCodeUsed(id) {
  db.prepare(`UPDATE verification_codes SET used_at = ? WHERE id = ?`)
    .run(nowMs(), id);
}

function incrementCodeAttempts(id) {
  db.prepare(`UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?`)
    .run(id);
}

// Sessions
function createSession(userId, days = 7) {
  const id = uuid();
  const created = nowMs();
  const expires = created + days * 24 * 60 * 60 * 1000;
  db.prepare(`
    INSERT INTO sessions (id, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(id, userId, created, expires);
  return { id, user_id: userId, created_at: created, expires_at: expires };
}

function getSession(id) {
  return db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(id);
}

function deleteSession(id) {
  db.prepare(`DELETE FROM sessions WHERE id = ?`).run(id);
}

function deleteSessionsForUser(userId) {
  db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
}

// Masking (for /me)
function maskPhone(p) {
  if (!p) return "";
  const digits = p.replace(/\D/g, "");
  if (digits.length < 4) return "***";
  return `(***) ***-${digits.slice(-4)}`;
}

// Stub email/SMS (replace with real providers later)
async function sendEmail(to, subject, body) {
  console.log("[EMAIL]", to, subject, body);
}
async function sendSms(to, body) {
  console.log("[SMS]", to, body);
}

// ---------- AUTH MIDDLEWARE ----------

function authRequired(req, res, next) {
  const sid = req.cookies.ff_session;
  if (!sid) {
    return res.status(401).json({ error: "unauthenticated" });
  }

  const session = getSession(sid);
  const now = nowMs();

  if (!session || session.expires_at < now) {
    if (sid) deleteSession(sid);
    res.clearCookie("ff_session");
    return res.status(401).json({ error: "unauthenticated" });
  }

  const user = getUserById(session.user_id);
  if (!user || user.status !== "active") {
    deleteSession(sid);
    res.clearCookie("ff_session");
    return res.status(401).json({ error: "unauthenticated" });
  }

  req.user = user;
  next();
}

// ---------- ROUTES ----------

// Signup: create pending user + send both codes
app.post("/auth/signup", async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      password,
      locale = "en",
      theme = "system",
      termsVersion = "2025-11-04",
      privacyVersion = "2025-11-04"
    } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: "missing_fields" });
    }

    if (getUserByEmail(email)) {
      return res.status(400).json({ error: "email_in_use" });
    }

    const passwordHash = await argon2.hash(password);
    const user = insertUser({ name, email, phone, passwordHash, locale, theme });

    db.prepare(`
      INSERT INTO user_consents (id, user_id, terms_version, privacy_version, locale, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      uuid(),
      user.id,
      termsVersion,
      privacyVersion,
      locale,
      new Date().toISOString()
    );

    const emailCode = await createVerificationCode(user.id, "email");
    const phoneCode = await createVerificationCode(user.id, "phone");

    await sendEmail(user.email, "Verify your email for FF Reserve", `Your code is ${emailCode}`);
    await sendSms(user.phone, `FF Reserve verification code: ${phoneCode}`);

    return res.json({ ok: true, userId: user.id });
  } catch (err) {
    console.error("signup_failed", err);
    return res.status(500).json({ error: "signup_failed" });
  }
});

// Verify email
app.post("/auth/verify-email", async (req, res) => {
  const { userId, code } = req.body;
  if (!userId || !code) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const user = getUserById(userId);
  if (!user) return res.status(400).json({ error: "invalid_user" });

  const rec = getLatestCode(userId, "email");
  if (!rec) return res.status(400).json({ error: "code_expired" });

  const ok = await argon2.verify(rec.code_hash, code).catch(() => false);
  if (!ok) {
    incrementCodeAttempts(rec.id);
    return res.status(400).json({ error: "invalid_code" });
  }

  markCodeUsed(rec.id);

  const updated = updateUser(userId, { email_verified: 1 });
  if (updated.email_verified && updated.phone_verified && updated.status !== "active") {
    updateUser(userId, { status: "active" });
  }

  return res.json({ ok: true });
});

// Verify phone
app.post("/auth/verify-phone", async (req, res) => {
  const { userId, code } = req.body;
  if (!userId || !code) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const user = getUserById(userId);
  if (!user) return res.status(400).json({ error: "invalid_user" });

  const rec = getLatestCode(userId, "phone");
  if (!rec) return res.status(400).json({ error: "code_expired" });

  const ok = await argon2.verify(rec.code_hash, code).catch(() => false);
  if (!ok) {
    incrementCodeAttempts(rec.id);
    return res.status(400).json({ error: "invalid_code" });
  }

  markCodeUsed(rec.id);

  const updated = updateUser(userId, { phone_verified: 1 });
  if (updated.email_verified && updated.phone_verified && updated.status !== "active") {
    updateUser(userId, { status: "active" });
  }

  return res.json({ ok: true });
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const user = getUserByEmail(email);
  if (!user) return res.status(400).json({ error: "invalid_credentials" });

  if (user.status !== "active" || !user.email_verified || !user.phone_verified) {
    return res.status(403).json({ error: "not_verified" });
  }

  const ok = await argon2.verify(user.password_hash, password).catch(() => false);
  if (!ok) {
    return res.status(400).json({ error: "invalid_credentials" });
  }

  const session = createSession(user.id);

  res.cookie("ff_session", session.id, {
    httpOnly: true,
    secure: false, // set true behind HTTPS/proxy in real deploy
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  return res.json({
    ok: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      locale: user.locale,
      theme: user.theme
    }
  });
});

// Logout
app.post("/auth/logout", authRequired, (req, res) => {
  const sid = req.cookies.ff_session;
  if (sid) deleteSession(sid);
  res.clearCookie("ff_session");
  res.json({ ok: true });
});

// Current user
app.get("/me", authRequired, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id,
    name: u.name,
    email: u.email,
    phone: maskPhone(u.phone),
    locale: u.locale,
    theme: u.theme,
    email_verified: !!u.email_verified,
    phone_verified: !!u.phone_verified,
    status: u.status
  });
});

// Update preferences (locale, theme)
app.patch("/settings/preferences", authRequired, (req, res) => {
  const u = req.user;
  const { theme, locale } = req.body;

  const allowedThemes = ["light", "dark", "system"];
  const newTheme = allowedThemes.includes(theme) ? theme : u.theme;
  const newLocale = typeof locale === "string" && locale.length <= 10
    ? locale
    : u.locale;

  const updated = updateUser(u.id, {
    theme: newTheme,
    locale: newLocale
  });

  res.json({
    ok: true,
    theme: updated.theme,
    locale: updated.locale
  });
});

// Delete account (hard delete)
app.delete("/account", authRequired, (req, res) => {
  const u = req.user;

  deleteSessionsForUser(u.id);
  db.prepare(`DELETE FROM verification_codes WHERE user_id = ?`).run(u.id);
  db.prepare(`DELETE FROM user_consents WHERE user_id = ?`).run(u.id);
  db.prepare(`DELETE FROM transactions WHERE user_id = ?`).run(u.id);
  db.prepare(`DELETE FROM users WHERE id = ?`).run(u.id);

  res.clearCookie("ff_session");
  res.json({ ok: true });
});

// Health check
app.get("/status", (req, res) => {
  res.json({
    status: "ok",
    app: "FF Reserve",
    time: new Date().toISOString()
  });
});

// ---------- START SERVER ----------

app.listen(PORT, () => {
  console.log(`FF Reserve backend running on port ${PORT}`);
});
