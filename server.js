const express = require("express");
const { Pool } = require("pg");
const { Resend } = require("resend");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});
app.use(express.static("public"));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const otps = new Map();
const verified = new Set();

function genOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function genCode() { return Math.random().toString(36).substring(2,8).toUpperCase(); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }

async function sendOTP(email, otp) {
  if (!resend) { console.log("[DEV] OTP for " + email + ": " + otp); return; }
  await resend.emails.send({
    from: "WHALENIZER <noreply@whalenizer.com>",
    to: email,
    subject: "Your WHALENIZER verification code",
    html: "<div style='background:#000;color:#00f5ff;padding:40px;font-family:monospace;text-align:center;border-radius:16px'><h1 style='letter-spacing:8px'>WHALENIZER</h1><p style='color:#888'>Your code:</p><div style='font-size:56px;font-weight:700;letter-spacing:12px;color:#fff'>" + otp + "</div><p style='color:#555;font-size:12px'>Expires in 10 minutes</p></div>"
  });
}

// ─── BONDING CURVE ───────────────────────────────────────────
const P0 = 0.001; // base price in ETH
const MULTIPLIER = 1.5;
function getPrice(supply) { return P0 * Math.pow(MULTIPLIER, supply); }
function getBuyPrice(supply) {
  const price = getPrice(supply);
  const fee = price * 0.05;
  return { price, fee, total: price + fee, creatorFee: fee * 0.5, treasuryFee: fee * 0.5 };
}
function getSellPrice(supply) {
  const price = getPrice(supply - 1);
  const fee = price * 0.05;
  return { price, fee, net: price - fee, creatorFee: fee * 0.5, treasuryFee: fee * 0.5 };
}

// ─── POINTS ──────────────────────────────────────────────────
const POINTS = { buy: 25, post: 10, login: 5, like: 2 };

async function addPoints(userId, action, ref) {
  const pts = POINTS[action] || 0;
  if (!pts) return;
  await pool.query(
    "INSERT INTO points_log (user_id, action, points, ref) VALUES ($1,$2,$3,$4)",
    [userId, action, pts, ref || null]
  );
  await pool.query("UPDATE app_users SET points = points + $1 WHERE id = $2", [pts, userId]);
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
async function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const r = await pool.query("SELECT * FROM app_users WHERE session_token=$1", [token]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid session' });
    req.user = r.rows[0];
    next();
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
}

// ─── DB INIT ─────────────────────────────────────────────────
async function initDB() {
  // Whitelist table (existing)
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

  // App users (full app, separate from whitelist)
  await pool.query(`CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    wallet TEXT,
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    points INTEGER DEFAULT 0,
    shares_supply INTEGER DEFAULT 0,
    session_token TEXT,
    invite_code TEXT UNIQUE,
    invited_by TEXT DEFAULT NULL,
    last_login TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  // Posts
  await pool.query(`CREATE TABLE IF NOT EXISTS posts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (char_length(content) <= 500),
    likes_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  // Likes
  await pool.query(`CREATE TABLE IF NOT EXISTS likes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
    post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, post_id)
  )`);

  // Trades
  await pool.query(`CREATE TABLE IF NOT EXISTS trades (
    id BIGSERIAL PRIMARY KEY,
    buyer_id BIGINT REFERENCES app_users(id),
    subject_id BIGINT REFERENCES app_users(id),
    type TEXT CHECK (type IN ('buy','sell')),
    shares INTEGER DEFAULT 1,
    price_eth NUMERIC(20,8),
    fee_eth NUMERIC(20,8),
    tx_hash TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  // Share holdings
  await pool.query(`CREATE TABLE IF NOT EXISTS holdings (
    id BIGSERIAL PRIMARY KEY,
    holder_id BIGINT REFERENCES app_users(id),
    subject_id BIGINT REFERENCES app_users(id),
    shares INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(holder_id, subject_id)
  )`);

  // Points log
  await pool.query(`CREATE TABLE IF NOT EXISTS points_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_users(id),
    action TEXT,
    points INTEGER,
    ref TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  console.log("DB ready");
}

// ═══════════════════════════════════════════════════════════════
// WHITELIST ROUTES (existing — unchanged)
// ═══════════════════════════════════════════════════════════════

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
    verified.delete(email);
    await sendOTP(email, otp);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.json({ error: "Failed to send OTP" }); }
});

app.post("/whitelist/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otps.get(email);
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) return res.json({ error: "Invalid or expired code" });
  verified.add(email);
  otps.delete(email);
  res.json({ ok: true });
});

app.post("/whitelist/apply", async (req, res) => {
  const { wallet, email, username, inviteCode } = req.body;
  if (!wallet || !email || !username) return res.json({ error: "All fields required" });
  if (!verified.has(email)) return res.json({ error: "Email not verified" });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.json({ error: "Invalid username format" });
  try {
    const count = await pool.query("SELECT COUNT(*) FROM whitelist");
    let position = parseInt(count.rows[0].count) + 1;
    const myCode = genCode();
    await pool.query("INSERT INTO whitelist (wallet,email,username,invite_code,invited_by,position) VALUES ($1,$2,$3,$4,$5,$6)", [wallet, email, username, myCode, inviteCode || null, position]);
    if (inviteCode) {
      const inviter = await pool.query("SELECT position FROM whitelist WHERE invite_code=$1", [inviteCode]);
      if (inviter.rows.length) {
        const ip = inviter.rows[0].position;
        if (ip > 1) {
          await pool.query("UPDATE whitelist SET position = position + 1 WHERE position >= $1 AND invite_code != $2", [ip - 1, inviteCode]);
          await pool.query("UPDATE whitelist SET position = $1 WHERE invite_code=$2", [ip - 1, inviteCode]);
        }
      }
    }
    verified.delete(email);
    const user = await pool.query("SELECT username, email, wallet, invite_code, position FROM whitelist WHERE email=$1", [email]);
    res.json({ ok: true, user: user.rows[0] });
  } catch(e) {
    if (e.code === "23505") return res.json({ error: "Email or username already registered" });
    console.error(e); res.json({ error: "Submission failed" });
  }
});

app.get("/whitelist/invite-stats/:code", async (req, res) => {
  try {
    const count = await pool.query("SELECT COUNT(*) FROM whitelist WHERE invited_by=$1", [req.params.code]);
    res.json({ invites: count.rows[0].count });
  } catch(e) { res.json({ error: "Server error" }); }
});

app.get("/admin/data", async (req, res) => {
  const { password } = req.query;
  if (password !== (process.env.ADMIN_PASSWORD || "whale2026")) return res.status(401).json({ error: "Unauthorized" });
  try {
    const users = await pool.query("SELECT position, username, email, wallet, invite_code, invited_by, created_at FROM whitelist ORDER BY position ASC");
    const total = users.rows.length;
    const invites = await pool.query("SELECT invited_by, COUNT(*) as count FROM whitelist WHERE invited_by IS NOT NULL GROUP BY invited_by ORDER BY count DESC");
    res.json({ total, users: users.rows, topInviters: invites.rows });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// APP AUTH ROUTES
// ═══════════════════════════════════════════════════════════════

// Send OTP for app login
app.post("/app/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ error: "Email required" });
  try {
    const otp = genOTP();
    otps.set('app:' + email, { otp, expires: Date.now() + 10 * 60 * 1000 });
    await sendOTP(email, otp);
    res.json({ ok: true });
  } catch(e) { res.json({ error: "Failed to send OTP" }); }
});

// Verify OTP + login or register
app.post("/app/auth/verify", async (req, res) => {
  const { email, otp, username, wallet } = req.body;
  const stored = otps.get('app:' + email);
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) return res.json({ error: "Invalid or expired code" });
  otps.delete('app:' + email);
  try {
    let user = (await pool.query("SELECT * FROM app_users WHERE email=$1", [email])).rows[0];
    const token = genToken();
    if (!user) {
      // New user — require username
      if (!username) return res.json({ error: "Username required", needUsername: true });
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.json({ error: "Invalid username" });
      const code = genCode();
      const r = await pool.query(
        "INSERT INTO app_users (email,username,wallet,invite_code,session_token) VALUES ($1,$2,$3,$4,$5) RETURNING *",
        [email, username, wallet || null, code, token]
      );
      user = r.rows[0];
    } else {
      // Existing user — update token + last_login + daily points
      const lastLogin = user.last_login ? new Date(user.last_login) : null;
      const now = new Date();
      const isNewDay = !lastLogin || (now - lastLogin) > 24 * 60 * 60 * 1000;
      await pool.query("UPDATE app_users SET session_token=$1, last_login=NOW() WHERE id=$2", [token, user.id]);
      if (isNewDay) await addPoints(user.id, 'login', null);
      user = (await pool.query("SELECT * FROM app_users WHERE id=$1", [user.id])).rows[0];
    }
    res.json({ ok: true, token, user: sanitizeUser(user) });
  } catch(e) {
    if (e.code === '23505') return res.json({ error: "Username already taken" });
    console.error(e); res.json({ error: "Server error" });
  }
});

app.post("/app/auth/logout", authMiddleware, async (req, res) => {
  await pool.query("UPDATE app_users SET session_token=NULL WHERE id=$1", [req.user.id]);
  res.json({ ok: true });
});

app.get("/app/auth/me", authMiddleware, async (req, res) => {
  res.json({ user: sanitizeUser(req.user) });
});

function sanitizeUser(u) {
  return { id: u.id, email: u.email, username: u.username, wallet: u.wallet, bio: u.bio, avatar: u.avatar, points: u.points, shares_supply: u.shares_supply, invite_code: u.invite_code, created_at: u.created_at };
}

// ═══════════════════════════════════════════════════════════════
// FEED ROUTES
// ═══════════════════════════════════════════════════════════════

// Get feed (global, paginated)
app.get("/app/feed", authMiddleware, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const r = await pool.query(`
      SELECT p.id, p.content, p.likes_count, p.created_at,
             u.id as user_id, u.username, u.avatar, u.points,
             EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=$3) as liked
      FROM posts p
      JOIN app_users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset, req.user.id]);
    res.json({ posts: r.rows });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

// Create post
app.post("/app/feed/post", authMiddleware, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length === 0) return res.json({ error: "Content required" });
  if (content.length > 500) return res.json({ error: "Max 500 characters" });
  try {
    const r = await pool.query(
      "INSERT INTO posts (user_id, content) VALUES ($1,$2) RETURNING *",
      [req.user.id, content.trim()]
    );
    await addPoints(req.user.id, 'post', r.rows[0].id.toString());
    const post = await pool.query(`
      SELECT p.*, u.username, u.avatar, u.points, false as liked
      FROM posts p JOIN app_users u ON u.id=p.user_id WHERE p.id=$1
    `, [r.rows[0].id]);
    res.json({ ok: true, post: post.rows[0] });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

// Like / unlike post
app.post("/app/feed/like/:postId", authMiddleware, async (req, res) => {
  const postId = req.params.postId;
  try {
    const existing = await pool.query("SELECT id FROM likes WHERE user_id=$1 AND post_id=$2", [req.user.id, postId]);
    if (existing.rows.length) {
      await pool.query("DELETE FROM likes WHERE user_id=$1 AND post_id=$2", [req.user.id, postId]);
      await pool.query("UPDATE posts SET likes_count = likes_count - 1 WHERE id=$1", [postId]);
      res.json({ liked: false });
    } else {
      await pool.query("INSERT INTO likes (user_id, post_id) VALUES ($1,$2)", [req.user.id, postId]);
      await pool.query("UPDATE posts SET likes_count = likes_count + 1 WHERE id=$1", [postId]);
      await addPoints(req.user.id, 'like', postId.toString());
      res.json({ liked: true });
    }
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

// Delete post
app.delete("/app/feed/post/:postId", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM posts WHERE id=$1 AND user_id=$2", [req.params.postId, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// PROFILE ROUTES
// ═══════════════════════════════════════════════════════════════

app.get("/app/profile/:username", authMiddleware, async (req, res) => {
  try {
    const u = await pool.query("SELECT id,username,bio,avatar,points,shares_supply,wallet,created_at FROM app_users WHERE username=$1", [req.params.username]);
    if (!u.rows.length) return res.json({ error: "User not found" });
    const user = u.rows[0];
    // posts
    const posts = await pool.query(`
      SELECT p.*, u.username, u.avatar,
             EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=$2) as liked
      FROM posts p JOIN app_users u ON u.id=p.user_id
      WHERE p.user_id=$1 ORDER BY p.created_at DESC LIMIT 20
    `, [user.id, req.user.id]);
    // holdings
    const holdings = await pool.query(`
      SELECT h.shares, u.username, u.avatar, u.shares_supply
      FROM holdings h JOIN app_users u ON u.id=h.subject_id
      WHERE h.holder_id=$1 AND h.shares > 0 ORDER BY h.shares DESC
    `, [user.id]);
    // price info
    const buyInfo = getBuyPrice(user.shares_supply);
    // my holding of this user
    const myHolding = req.user.id !== user.id
      ? await pool.query("SELECT shares FROM holdings WHERE holder_id=$1 AND subject_id=$2", [req.user.id, user.id])
      : null;
    res.json({
      user,
      posts: posts.rows,
      holdings: holdings.rows,
      buyPrice: buyInfo.total,
      sellPrice: user.shares_supply > 0 ? getSellPrice(user.shares_supply).net : 0,
      myShares: myHolding?.rows[0]?.shares || 0,
      isOwn: req.user.id === user.id
    });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

app.patch("/app/profile/update", authMiddleware, async (req, res) => {
  const { bio } = req.body;
  try {
    await pool.query("UPDATE app_users SET bio=$1 WHERE id=$2", [bio?.substring(0,160) || '', req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// TRADING ROUTES
// ═══════════════════════════════════════════════════════════════

// Get price quote
app.get("/app/trade/price/:username", authMiddleware, async (req, res) => {
  try {
    const u = await pool.query("SELECT id, shares_supply, username FROM app_users WHERE username=$1", [req.params.username]);
    if (!u.rows.length) return res.json({ error: "User not found" });
    const { shares_supply, id } = u.rows[0];
    const buy = getBuyPrice(shares_supply);
    const sell = shares_supply > 0 ? getSellPrice(shares_supply) : null;
    const myHolding = await pool.query("SELECT shares FROM holdings WHERE holder_id=$1 AND subject_id=$2", [req.user.id, id]);
    res.json({
      supply: shares_supply,
      buyPrice: buy.total,
      buyFee: buy.fee,
      sellPrice: sell ? sell.net : 0,
      myShares: myHolding.rows[0]?.shares || 0
    });
  } catch(e) { res.json({ error: "Server error" }); }
});

// Buy share (off-chain simulation — connects to on-chain tx_hash later)
app.post("/app/trade/buy/:username", authMiddleware, async (req, res) => {
  const { tx_hash } = req.body;
  try {
    const u = await pool.query("SELECT id, shares_supply FROM app_users WHERE username=$1 FOR UPDATE", [req.params.username]);
    if (!u.rows.length) return res.json({ error: "User not found" });
    const subject = u.rows[0];
    if (subject.id === req.user.id) return res.json({ error: "Cannot buy your own shares" });
    const priceInfo = getBuyPrice(subject.shares_supply);
    // Record trade
    await pool.query(
      "INSERT INTO trades (buyer_id, subject_id, type, shares, price_eth, fee_eth, tx_hash) VALUES ($1,$2,'buy',1,$3,$4,$5)",
      [req.user.id, subject.id, priceInfo.price, priceInfo.fee, tx_hash || null]
    );
    // Update supply
    await pool.query("UPDATE app_users SET shares_supply = shares_supply + 1 WHERE id=$1", [subject.id]);
    // Update holdings
    await pool.query(`
      INSERT INTO holdings (holder_id, subject_id, shares) VALUES ($1,$2,1)
      ON CONFLICT (holder_id, subject_id) DO UPDATE SET shares = holdings.shares + 1, updated_at = NOW()
    `, [req.user.id, subject.id]);
    // Points
    await addPoints(req.user.id, 'buy', subject.id.toString());
    res.json({ ok: true, price: priceInfo.total, newSupply: subject.shares_supply + 1 });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

// Sell share
app.post("/app/trade/sell/:username", authMiddleware, async (req, res) => {
  const { tx_hash } = req.body;
  try {
    const u = await pool.query("SELECT id, shares_supply FROM app_users WHERE username=$1 FOR UPDATE", [req.params.username]);
    if (!u.rows.length) return res.json({ error: "User not found" });
    const subject = u.rows[0];
    if (subject.shares_supply < 1) return res.json({ error: "No shares to sell" });
    const holding = await pool.query("SELECT shares FROM holdings WHERE holder_id=$1 AND subject_id=$2", [req.user.id, subject.id]);
    if (!holding.rows.length || holding.rows[0].shares < 1) return res.json({ error: "You don't own shares in this user" });
    const priceInfo = getSellPrice(subject.shares_supply);
    await pool.query(
      "INSERT INTO trades (buyer_id, subject_id, type, shares, price_eth, fee_eth, tx_hash) VALUES ($1,$2,'sell',1,$3,$4,$5)",
      [req.user.id, subject.id, priceInfo.price, priceInfo.fee, tx_hash || null]
    );
    await pool.query("UPDATE app_users SET shares_supply = shares_supply - 1 WHERE id=$1", [subject.id]);
    await pool.query("UPDATE holdings SET shares = shares - 1, updated_at = NOW() WHERE holder_id=$1 AND subject_id=$2", [req.user.id, subject.id]);
    res.json({ ok: true, price: priceInfo.net, newSupply: subject.shares_supply - 1 });
  } catch(e) { console.error(e); res.json({ error: "Server error" }); }
});

// Recent trades for a user
app.get("/app/trade/history/:username", authMiddleware, async (req, res) => {
  try {
    const u = await pool.query("SELECT id FROM app_users WHERE username=$1", [req.params.username]);
    if (!u.rows.length) return res.json({ error: "User not found" });
    const r = await pool.query(`
      SELECT t.type, t.shares, t.price_eth, t.fee_eth, t.created_at,
             b.username as buyer_username, b.avatar as buyer_avatar
      FROM trades t
      JOIN app_users b ON b.id = t.buyer_id
      WHERE t.subject_id=$1
      ORDER BY t.created_at DESC LIMIT 20
    `, [u.rows[0].id]);
    res.json({ trades: r.rows });
  } catch(e) { res.json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// LEADERBOARD
// ═══════════════════════════════════════════════════════════════

app.get("/app/leaderboard", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT id, username, avatar, points, shares_supply,
             RANK() OVER (ORDER BY points DESC) as rank
      FROM app_users ORDER BY points DESC LIMIT 50
    `);
    res.json({ leaderboard: r.rows });
  } catch(e) { res.json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// SEARCH
// ═══════════════════════════════════════════════════════════════

app.get("/app/search", authMiddleware, async (req, res) => {
  const q = req.query.q?.trim();
  if (!q || q.length < 2) return res.json({ results: [] });
  try {
    const r = await pool.query(
      "SELECT id, username, avatar, points, shares_supply FROM app_users WHERE username ILIKE $1 LIMIT 10",
      ['%' + q + '%']
    );
    res.json({ results: r.rows });
  } catch(e) { res.json({ error: "Server error" }); }
});

// ═══════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════

app.listen(3000, async () => { await initDB(); console.log("Server running on port 3000"); });