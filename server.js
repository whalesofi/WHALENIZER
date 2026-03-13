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
  await resend.emails.send({ from: "WHALENIZER <noreply@whalenizer.com>", to: email, subject: "Your WHALENIZER verification code", html: "<div style='background:#000;color:#00f5ff;padding:40px;font-family:monospace;text-align:center'><h1>WHALENIZER</h1><p style='color:#888'>Your code:</p><div style='font-size:56px;font-weight:700;color:#fff'>" + otp + "</div><p style='color:#555;font-size:12px'>Expires in 10 minutes</p></div>" });
}
async function initDB() {
  await pool.query("CREATE TABLE IF NOT EXISTS whitelist (id BIGSERIAL PRIMARY KEY, wallet TEXT NOT NULL, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT NOW())");
  console.log("DB ready");
}
app.post("/whitelist/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ error: "Email required" });
  try {
    const exists = await pool.query("SELECT id FROM whitelist WHERE email=$1", [email]);
    if (exists.rows.length) return res.json({ error: "Email already registered" });
    const otp = genOTP();
    otps.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 });
    await sendOTP(email, otp);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.json({ error: "Failed to send OTP" }); }
});
app.post("/whitelist/apply", async (req, res) => {
  const { wallet, email, username, otp } = req.body;
  if (!wallet || !email || !username || !otp) return res.json({ error: "All fields required" });
  const stored = otps.get(email);
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) return res.json({ error: "Invalid or expired code" });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.json({ error: "Invalid username format" });
  try {
    await pool.query("INSERT INTO whitelist (wallet,email,username) VALUES ($1,$2,$3)", [wallet, email, username]);
    otps.delete(email);
    const count = await pool.query("SELECT COUNT(*) FROM whitelist");
    res.json({ ok: true, position: count.rows[0].count });
  } catch(e) {
    if (e.code === "23505") return res.json({ error: "Email or username already registered" });
    console.error(e); res.json({ error: "Submission failed" });
  }
});
app.listen(3000, async () => { await initDB(); console.log("Server running"); });