require('dotenv').config();
const express = require('express'), crypto = require('crypto'), path = require('path');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), helmet = require('helmet');
const cookieParser = require('cookie-parser'), rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

const { JWT_SECRET, PAYSTACK_SECRET_KEY: PSK, BASE_URL = 'http://localhost:3000' } = process.env;
if (!JWT_SECRET || !PSK) throw new Error('Set JWT_SECRET and PAYSTACK_SECRET_KEY in .env');
const FEE_KOBO = 100000; // ₦1,000

const db = new Database('hub.db'); db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', payment_status TEXT NOT NULL DEFAULT 'unpaid',
  paid_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  reference TEXT UNIQUE NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  gateway TEXT DEFAULT 'paystack', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payment_webhooks(id INTEGER PRIMARY KEY, event TEXT, reference TEXT, payload TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY, title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
  description TEXT, thumbnail TEXT, category_id INTEGER REFERENCES categories(id), instructor TEXT, level TEXT,
  duration TEXT, published INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY, course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title TEXT NOT NULL, video_url TEXT, resource_url TEXT, position INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS lesson_progress(user_id INTEGER, lesson_id INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
  completed_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, lesson_id));
CREATE TABLE IF NOT EXISTS ebooks(id INTEGER PRIMARY KEY, title TEXT NOT NULL, author TEXT, description TEXT, cover TEXT,
  category_id INTEGER REFERENCES categories(id), file_url TEXT, allow_download INTEGER DEFAULT 0,
  published INTEGER DEFAULT 0, published_on TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commissions(id INTEGER PRIMARY KEY, referrer_id INTEGER NOT NULL REFERENCES users(id),
  referred_id INTEGER NOT NULL UNIQUE REFERENCES users(id), payment_id INTEGER NOT NULL UNIQUE REFERENCES payments(id),
  amount INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), amount INTEGER NOT NULL,
  bank_name TEXT, account_number TEXT, account_name TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES('referrals_enabled','1'),('commission_amount_naira','200'),('min_withdrawal_naira','1000');
DELETE FROM settings WHERE key='commission_percent';
`);
for (const c of ['email_norm TEXT', 'referral_code TEXT', 'referred_by INTEGER', 'signup_ip TEXT', 'suspended INTEGER DEFAULT 0'])
  if (!db.prepare('PRAGMA table_info(users)').all().some(x => x.name === c.split(' ')[0])) db.exec('ALTER TABLE users ADD COLUMN ' + c);
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_ref ON users(referral_code); CREATE INDEX IF NOT EXISTS ix_ip ON users(signup_ip)');
const getSetting = k => db.prepare('SELECT value FROM settings WHERE key=?').get(k).value;
const norm = e => { let [l, d] = e.split('@'); l = l.split('+')[0]; if (/^(gmail|googlemail)\.com$/.test(d)) l = l.replace(/\./g, ''); return l + '@' + d; };
const newCode = () => crypto.randomBytes(4).toString('hex');
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && !db.prepare('SELECT 1 FROM users WHERE email=?').get(process.env.ADMIN_EMAIL))
  db.prepare("INSERT INTO users(name,email,password_hash,role,payment_status) VALUES('Admin',?,?, 'admin','paid')")
    .run(process.env.ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cookieParser());

// ---- Paystack helpers ----
const ps = (p, opt = {}) => fetch('https://api.paystack.co' + p, { ...opt,
  headers: { Authorization: `Bearer ${PSK}`, 'Content-Type': 'application/json' } }).then(r => r.json());

// Idempotent activation: only after server-side verification with Paystack.
function credit(pay) {
  const u = db.prepare('SELECT referred_by FROM users WHERE id=?').get(pay.user_id);
  if (!u || !u.referred_by || u.referred_by === pay.user_id || getSetting('referrals_enabled') !== '1') return;
  const rf = db.prepare('SELECT suspended FROM users WHERE id=?').get(u.referred_by);
  if (!rf || rf.suspended) return;
  const amt = Math.round(Number(getSetting('commission_amount_naira')) * 100); // fixed amount, set by admin
  if (amt > 0) db.prepare('INSERT OR IGNORE INTO commissions(referrer_id,referred_id,payment_id,amount) VALUES(?,?,?,?)').run(u.referred_by, pay.user_id, pay.id, amt);
}
function settle(reference, data) {
  return db.transaction(() => {
    const pay = db.prepare('SELECT * FROM payments WHERE reference=?').get(reference);
