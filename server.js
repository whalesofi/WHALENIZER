const express = require("express");
const { Pool } = require("pg");
const { Resend } = require("resend");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const otps = new Map();

function genOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }

async function sendOTP(email, otp) {
  if (!resend) { console.log("[DEV] OTP for " + email + ": " + otp); return; }
  await resend.emails.send({
    from: "WHALENIZER <noreply@whalenizer.com>",
    to: email,
    subject: "Your WHALENIZER verification code",
    html: "<div style='background:#000;color:#00f5ff;padding:40px;font-family:monospace;text-align:center;border-radius:16px'><h1 style='letter-spacing:8px'>WHALENIZER</h1><p style='color:#888'>Your code:</p><div style='font-size:56px;font-weight:700;letter-spacing:12px;color:#fff'>" + otp + "</div><p style='color:#555;font-size:12px'>Expires in 10 minutes</p></div>"
  });
}

async function initDB() {
  await pool.query(`CREATE TABLE IF NOT EXISTS whitelist (
    id BIGSERIAL PRIMARY KEY,
    wallet TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    invited_by TEXT DEFAULT NULL,
    position INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invites (
    id BIGSERIAL PRIMARY KEY,
    inviter_email TEXT NOT NULL,
    invited_email TEXT,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
  )`);
  console.log("DB ready");
}

function genCode() { return Math.random().toString(36).substring(2,8).toUpperCase(); }

app.post("/whitelist/check-email", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ error: "Email required" });
  try {
    const exists = await pool.query("SELECT id, username, email, wallet, invite_code, position FROM whitelist WHERE email=$1", [email]);
    if (exists.rows.length) return res.json({ exists: true, user: exists.rows[0] });
    return res.json({ exists: false });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

app.post("/whitelist/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ error: "Email required" });
  try {
    const otp = genOTP();
    otps.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 });
    await sendOTP(email, otp);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.json({ error: "Failed to send OTP" }); }
});

app.post("/whitelist/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otps.get(email);
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) return res.json({ error: "Invalid or expired code" });
  res.json({ ok: true });
});

app.post("/whitelist/apply", async (req, res) => {
  const { wallet, email, username, otp, inviteCode } = req.body;
  if (!wallet || !email || !username || !otp) return res.json({ error: "All fields required" });
  const stored = otps.get(email);
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) return res.json({ error: "Invalid or expired code" });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.json({ error: "Invalid username format" });
  try {
    const count = await pool.query("SELECT COUNT(*) FROM whitelist");
    let position = parseInt(count.rows[0].count) + 1;
    const myCode = genCode();
    await pool.query("INSERT INTO whitelist (wallet,email,username,invite_code,invited_by,position) VALUES ($1,$2,$3,$4,$5,$6)",
      [wallet, email, username, myCode, inviteCode || null, position]);
    if (inviteCode) {
      const inviter = await pool.query("SELECT id, position FROM whitelist WHERE invite_code=$1", [inviteCode]);
      if (inviter.rows.length) {
        const inviterPos = inviter.rows[0].position;
        if (inviterPos > 1) {
          await pool.query("UPDATE whitelist SET position = position + 1 WHERE position >= $1 AND invite_code != $2", [inviterPos - 1, inviteCode]);
          await pool.query("UPDATE whitelist SET position = $1 WHERE invite_code=$2", [inviterPos - 1, inviteCode]);
          position = parseInt(count.rows[0].count) + 1;
        }
        await pool.query("INSERT INTO invites (inviter_email, invited_email, used) VALUES ($1,$2,true)",
          [inviter.rows[0].id, email]);
      }
    }
    otps.delete(email);
    const user = await pool.query("SELECT username, email, wallet, invite_code, position FROM whitelist WHERE email=$1", [email]);
    res.json({ ok: true, user: user.rows[0] });
  } catch(e) {
    if (e.code === "23505") return res.json({ error: "Email or username already registered" });
    console.error(e); res.json({ error: "Submission failed" });
  }
});

app.get("/whitelist/invite-stats/:code", async (req, res) => {
  try {
    const user = await pool.query("SELECT username, position FROM whitelist WHERE invite_code=$1", [req.params.code]);
    if (!user.rows.length) return res.json({ error: "Not found" });
    const invites = await pool.query("SELECT COUNT(*) FROM invites WHERE inviter_email=(SELECT id FROM whitelist WHERE invite_code=$1)", [req.params.code]);
    res.json({ username: user.rows[0].username, position: user.rows[0].position, invites: invites.rows[0].count });
  } catch(e) { res.json({ error: "Server error" }); }
});

app.listen(3000, async () => { await initDB(); console.log("Server running"); });