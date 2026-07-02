import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import pg from "pg";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const adminPassword = process.env.ADMIN_PASSWORD || "change-this-password";
const sessionSecret = process.env.SESSION_SECRET || adminPassword;
const databaseUrl = process.env.DATABASE_URL || "";
const basePath = path.join(__dirname, "public", "base.html");
const fallbackPath = path.join(__dirname, "published.html");
const pool = databaseUrl ? new pg.Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } }) : null;

app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

function sessionToken() {
  return crypto.createHmac("sha256", sessionSecret).update("txo-admin").digest("hex");
}

function cookies(req) {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((item) => item.trim().split("="))
      .filter(([key]) => key)
  );
}

function requireAdmin(req, res, next) {
  if (cookies(req).txo_admin !== sessionToken()) return res.status(401).json({ error: "管理者ログインが必要です" });
  next();
}

async function ensureTable() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS txo_site_content (
      id INTEGER PRIMARY KEY,
      html TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function readPublished() {
  if (pool) {
    await ensureTable();
    const result = await pool.query("SELECT html FROM txo_site_content WHERE id = 1");
    if (result.rows[0]?.html) return result.rows[0].html;
  } else {
    try {
      return await fs.readFile(fallbackPath, "utf8");
    } catch {
      // Use the bundled base until the first publish.
    }
  }
  return fs.readFile(basePath, "utf8");
}

async function writePublished(html) {
  if (pool) {
    await ensureTable();
    await pool.query(
      `INSERT INTO txo_site_content (id, html, updated_at) VALUES (1, $1, NOW())
       ON CONFLICT (id) DO UPDATE SET html = EXCLUDED.html, updated_at = NOW()`,
      [html]
    );
  } else {
    await fs.writeFile(fallbackPath, html, "utf8");
  }
}

app.post("/api/login", (req, res) => {
  if (req.body?.password !== adminPassword) return res.status(401).json({ error: "パスワードが違います" });
  res.cookie("txo_admin", sessionToken(), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
  res.json({ success: true });
});

app.get("/api/content", requireAdmin, async (_req, res) => {
  res.type("html").send(await readPublished());
});

app.put("/api/content", requireAdmin, async (req, res) => {
  const html = String(req.body?.html || "");
  if (!html.includes("<html") || html.length > 45_000_000) return res.status(400).json({ error: "HTMLデータが不正です" });
  await writePublished(html);
  res.json({ success: true });
});

app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "public", "editor.html")));
app.get("/preview", async (_req, res) => res.type("html").send(await readPublished()));
app.get("/", async (_req, res) => res.type("html").send(await readPublished()));

app.listen(port, () => console.log(`TXO public site listening on ${port}`));
