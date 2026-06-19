import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MultiServerManager } from "./multi-server-manager.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const adminPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(12).toString("base64url");
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const sessionDir = path.resolve(process.env.SESSION_DIR || defaultSessionDir(rootDir));
const usingGeneratedPassword = !process.env.ADMIN_PASSWORD;
const loginFailures = new Map();
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const MAX_LOGIN_FAILURES = 8;

if (isProduction && !process.env.ADMIN_PASSWORD) {
  throw new Error("ADMIN_PASSWORD doit etre defini en production.");
}

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET doit etre defini en production.");
}

function createFileSessionStore(dir) {
  class PersistentSessionStore extends session.Store {
    constructor() {
      super();
      this.dir = dir;
      fs.mkdirSync(this.dir, { recursive: true });
    }

    get(sid, callback) {
      fsp.readFile(this.fileFor(sid), "utf8")
        .then((content) => callback(null, JSON.parse(content)))
        .catch((error) => callback(error.code === "ENOENT" ? null : error));
    }

    set(sid, sess, callback) {
      const content = JSON.stringify(sess);
      fsp.mkdir(this.dir, { recursive: true })
        .then(() => fsp.writeFile(this.fileFor(sid), content, "utf8"))
        .then(() => callback?.())
        .catch((error) => callback?.(error));
    }

    destroy(sid, callback) {
      fsp.rm(this.fileFor(sid), { force: true })
        .then(() => callback?.())
        .catch((error) => callback?.(error));
    }

    touch(sid, sess, callback) {
      this.set(sid, sess, callback);
    }

    fileFor(sid) {
      const safeName = crypto.createHash("sha256").update(String(sid)).digest("hex");
      return path.join(this.dir, `${safeName}.json`);
    }
  }

  return new PersistentSessionStore();
}

const fleet = new MultiServerManager({
  rootDir,
  serverDir: process.env.SERVER_DIR,
  instancesRoot: process.env.SERVERS_DIR,
  backupRoot: process.env.BACKUP_ROOT,
  seedDir: process.env.SEED_DIR,
  downloadUrl: process.env.BDS_DOWNLOAD_URL,
  autoStart: process.env.AUTO_START !== "false"
});

await fleet.initialize();

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(securityHeaders);
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "512kb" }));
app.use(
  session({
    name: "bedrock_panel",
    secret: sessionSecret,
    store: createFileSessionStore(sessionDir),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);
app.use(csrfProtection);

function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Non connecte" });
  return res.redirect("/login");
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function serverFrom(req) {
  return fleet.require(req.params.id).manager;
}

function securityHeaders(_req, res, next) {
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
}

function csrfProtection(req, res, next) {
  if (req.session && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  }
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || req.path === "/login") return next();
  if (!req.session?.authenticated) return next();
  const token = String(req.get("x-csrf-token") || req.body?._csrf || req.query?._csrf || "");
  if (safeCompare(token, req.session.csrfToken || "")) return next();
  return res.status(403).json({ error: "Token CSRF invalide." });
}

app.get("/assets/lucide.min.js", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=604800, immutable");
  res.sendFile(path.join(rootDir, "node_modules", "lucide", "dist", "umd", "lucide.min.js"));
});

app.get("/login", (req, res) => {
  if (req.session?.authenticated) return res.redirect("/");
  res.type("html").send(loginHtml());
});

app.post("/login", (req, res) => {
  if (isLoginLimited(req.ip)) {
    return res.status(429).type("html").send(loginHtml("Trop de tentatives. Reessaie dans quelques minutes."));
  }
  const password = String(req.body.password || "");
  const ok = safeCompare(password, adminPassword);
  if (!ok) {
    recordFailedLogin(req.ip);
    return res.status(401).type("html").send(loginHtml("Mot de passe incorrect."));
  }
  clearFailedLogins(req.ip);
  req.session.authenticated = true;
  res.redirect("/");
});

app.post("/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/", requireAuth, (req, res) => {
  res.type("html").send(panelHtml(req.session.csrfToken));
});

app.get("/api/servers", requireAuth, asyncRoute(async (_req, res) => {
  res.json({ servers: await fleet.list() });
}));

app.post("/api/servers", requireAuth, asyncRoute(async (req, res) => {
  const server = await fleet.create({
    name: req.body.name,
    port: req.body.port,
    autoStart: Boolean(req.body.autoStart),
    templateServerId: req.body.templateServerId
  });
  res.status(201).json({ ok: true, server });
}));

app.patch("/api/servers/:id", requireAuth, asyncRoute(async (req, res) => {
  const server = await fleet.update(req.params.id, {
    name: req.body.name,
    port: req.body.port,
    autoStart: req.body.autoStart,
    resources: req.body.resources
  });
  res.json({ ok: true, server });
}));

app.delete("/api/servers/:id", requireAuth, asyncRoute(async (req, res) => {
  const server = fleet.require(req.params.id).meta;
  requireConfirmation(req, server.name);
  await fleet.delete(req.params.id);
  res.json({ ok: true });
}));

app.get("/api/servers/:id/status", requireAuth, asyncRoute(async (req, res) => {
  res.json(await serverFrom(req).status());
}));

app.get("/api/servers/:id/logs", requireAuth, (req, res) => {
  res.json({ logs: serverFrom(req).logs(Number(req.query.limit || 300)) });
});

app.post("/api/servers/:id/start", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).start();
  res.json({ ok: true });
}));

app.post("/api/servers/:id/stop", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).stop();
  res.json({ ok: true });
}));

app.post("/api/servers/:id/restart", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).restart();
  res.json({ ok: true });
}));

app.post("/api/servers/:id/reinstall", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, "REINSTALL");
  const result = await serverFrom(req).reinstall();
  res.json({ ok: true, ...result });
}));

app.post("/api/servers/:id/command", requireAuth, asyncRoute(async (req, res) => {
  const command = String(req.body.command || "").trim();
  if (!command) return res.status(400).json({ error: "Commande vide" });
  serverFrom(req).sendCommand(command);
  res.json({ ok: true });
}));

app.get("/api/servers/:id/properties", requireAuth, asyncRoute(async (req, res) => {
  res.json({ content: await serverFrom(req).readProperties() });
}));

app.put("/api/servers/:id/properties", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).writeProperties(String(req.body.content || ""));
  res.json({ ok: true });
}));

app.get("/api/servers/:id/properties-form", requireAuth, asyncRoute(async (req, res) => {
  const content = await serverFrom(req).readProperties();
  res.json({ values: parseProperties(content) });
}));

app.put("/api/servers/:id/properties-form", requireAuth, asyncRoute(async (req, res) => {
  const manager = serverFrom(req);
  const current = await manager.readProperties();
  await manager.writeProperties(mergeProperties(current, normalizePropertyPatch(req.body.values || {})));
  res.json({ ok: true });
}));

app.get("/api/servers/:id/files", requireAuth, asyncRoute(async (req, res) => {
  res.json({ files: await serverFrom(req).listFiles(String(req.query.path || "")) });
}));

app.get("/api/servers/:id/file", requireAuth, asyncRoute(async (req, res) => {
  res.json({ content: await serverFrom(req).readFile(String(req.query.path || "")) });
}));

app.put("/api/servers/:id/file", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).writeFile(String(req.body.path || ""), String(req.body.content || ""));
  res.json({ ok: true });
}));

app.post("/api/servers/:id/directory", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).makeDirectory(String(req.body.path || ""));
  res.json({ ok: true });
}));

app.delete("/api/servers/:id/file", requireAuth, asyncRoute(async (req, res) => {
  const target = String(req.query.path || "");
  requireConfirmation(req, target);
  await serverFrom(req).deleteFile(target);
  res.json({ ok: true });
}));

app.get("/api/servers/:id/backups", requireAuth, asyncRoute(async (req, res) => {
  res.json({ backups: await serverFrom(req).listBackups() });
}));

app.post("/api/servers/:id/backups", requireAuth, asyncRoute(async (req, res) => {
  const backup = await serverFrom(req).createBackup();
  res.json({ ok: true, backup });
}));

app.get("/api/servers/:id/backups/:name", requireAuth, asyncRoute(async (req, res) => {
  const file = await serverFrom(req).resolveBackup(req.params.name);
  res.download(file);
}));

app.post("/api/servers/:id/backups/:name/restore", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, "RESTORE");
  await serverFrom(req).restoreBackup(req.params.name);
  res.json({ ok: true });
}));

app.delete("/api/servers/:id/backups/:name", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, req.params.name);
  await serverFrom(req).deleteBackup(req.params.name);
  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Erreur serveur" });
});

if (usingGeneratedPassword) {
  console.log(`ADMIN_PASSWORD genere pour cette session: ${adminPassword}`);
  console.log("Definis ADMIN_PASSWORD dans Railway pour garder un mot de passe stable.");
}

app.listen(port, () => {
  console.log(`Interface Bedrock prete sur le port ${port}`);
});

await fleet.startAutoServers();

function loginHtml(error = "") {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bedrock Host Panel</title>
  <style>
    :root { color-scheme: dark; --ink:#f7f8ff; --line:#394059; --panel:#272c42; --blue:#5b8cff; --red:#ff8d91; --bg:#111522; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; background:radial-gradient(circle at 80% 0%, rgba(91,140,255,.2), transparent 32%), var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    main { width:min(430px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:30px; box-shadow:0 18px 50px rgba(0,0,0,.28); }
    h1 { margin:0 0 20px; font-size:30px; font-weight:900; letter-spacing:0; }
    h1::first-letter { color:var(--blue); }
    label { display:block; margin:0 0 8px; font-size:12px; font-weight:900; text-transform:uppercase; color:#a8afc9; }
    input { width:100%; height:46px; border:1px solid var(--line); border-radius:8px; padding:0 12px; font:inherit; background:#20263a; color:var(--ink); }
    input:focus { outline:2px solid rgba(91,140,255,.24); border-color:var(--blue); }
    button { margin-top:16px; width:100%; height:46px; border:0; border-radius:7px; color:#fff; background:var(--blue); font:900 15px inherit; cursor:pointer; }
    p { min-height:22px; margin:10px 0 0; color:var(--red); }
  </style>
</head>
<body>
  <main>
    <h1>Bedrock Host Panel</h1>
    <form method="post" action="/login">
      <label for="password">Mot de passe</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Connexion</button>
      <p>${escapeHtml(error)}</p>
    </form>
  </main>
</body>
</html>`;
}

function panelHtml(csrfToken = "") {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bedrock Host Panel</title>
  <script src="/assets/lucide.min.js"></script>
  <style>
    :root { --ink:#f7f8ff; --muted:#a8afc9; --bg:#111522; --panel:#272c42; --panel-2:#303650; --panel-3:#1c2234; --line:#394059; --blue:#5b8cff; --blue-2:#223763; --red:#ff5d62; --green:#54d18a; --amber:#f2b85b; --code:#111521; --soft:#202842; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:#151820; color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; letter-spacing:0; }
    body::before { content:""; position:fixed; inset:0; pointer-events:none; background-image:linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px); background-size:32px 32px; }
    h1 { margin:0; font-size:32px; font-weight:900; }
    h2 { margin:0; font-size:18px; font-weight:900; }
    h3 { margin:0 0 10px; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
    .shell { position:relative; z-index:1; min-height:100vh; display:grid; grid-template-columns:296px minmax(0, 1fr); }
    .sidebar { position:sticky; top:0; min-height:100vh; max-height:100vh; overflow:auto; padding:18px 18px 22px; background:rgba(27,32,50,.92); border-right:1px solid rgba(255,255,255,.06); display:grid; align-content:start; gap:22px; }
    .brand { display:flex; align-items:center; gap:12px; min-height:44px; font-size:25px; font-weight:950; letter-spacing:.02em; }
    .brand-mark { width:34px; height:34px; border-radius:8px; display:grid; place-items:center; background:linear-gradient(135deg, #1db7ff, #6c7bff); color:#fff; box-shadow:0 12px 24px rgba(29,183,255,.22); }
    .side-group { display:grid; gap:8px; }
    .side-group.compact .content { padding:14px; }
    .nav-item { min-height:42px; display:flex; align-items:center; gap:12px; color:var(--muted); padding:0 10px; border-radius:7px; font-weight:800; }
    .nav-item.active { color:#76a6ff; background:#22304f; }
    .plan-card { border:1px solid #425070; background:#2b3149; border-radius:8px; padding:12px; display:grid; gap:4px; box-shadow:inset 4px 0 0 var(--blue); }
    .plan-title { display:flex; align-items:center; gap:9px; font-weight:900; }
    .main { min-width:0; padding:22px 24px 36px; display:grid; gap:18px; align-content:start; }
    .view { display:none; }
    .view.active { display:grid; gap:18px; }
    .overview-hero { min-height:96px; display:flex; align-items:flex-end; justify-content:space-between; gap:18px; padding:6px 0 0; }
    .overview-hero p { margin:8px 0 0; color:var(--muted); font-weight:800; }
    .topbar { display:grid; gap:16px; padding:2px 0 0; }
    .crumb { min-height:0; padding:0; border:0; background:transparent; color:var(--muted); font-weight:800; display:flex; align-items:center; justify-content:flex-start; gap:8px; }
    .crumb:hover { background:transparent; color:#dce4ff; }
    .hero { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; }
    .hero > div:first-child { min-width:260px; }
    .hero .actions { justify-content:flex-end; }
    .hero-meta { display:flex; flex-wrap:wrap; gap:18px; color:var(--muted); font-weight:800; }
    .hero-meta span { display:inline-flex; align-items:center; gap:7px; }
    .tabs-nav { min-height:58px; display:flex; align-items:center; justify-content:space-between; gap:12px; background:rgba(47,54,79,.92); border:1px solid var(--line); border-radius:8px; padding:8px; }
    .tab-list { display:flex; gap:6px; flex-wrap:wrap; }
    .tab { min-height:40px; border-radius:7px; padding:0 14px; border:0; background:transparent; display:inline-flex; align-items:center; color:var(--muted); font-weight:900; }
    .tab:hover { background:#343c58; }
    .tab.active { color:#79a9ff; background:#263d6a; }
    .panel, section { min-width:0; background:rgba(42,48,72,.94); border:1px solid var(--line); border-radius:8px; overflow:hidden; box-shadow:0 16px 40px rgba(0,0,0,.14); }
    .head { min-height:62px; padding:16px 18px; border-bottom:1px solid rgba(255,255,255,.06); display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .content { padding:18px; }
    .actions { display:flex; flex-wrap:wrap; gap:8px; }
    button, a.button { min-height:42px; border:1px solid transparent; border-radius:7px; background:#39415e; color:var(--ink); padding:0 14px; display:inline-flex; align-items:center; justify-content:center; gap:8px; font:900 14px inherit; cursor:pointer; text-decoration:none; transition:background .15s ease, transform .15s ease, border-color .15s ease; }
    button:hover, a.button:hover { background:#455072; }
    button:active, a.button:active { transform:scale(.98); }
    button.primary { background:var(--blue); border-color:var(--blue); color:#fff; }
    button.primary:hover { background:#6d9aff; }
    button.blue { background:#3a86ff; border-color:#3a86ff; color:#fff; }
    button.blue:hover { background:#4f95ff; }
    button.red { background:var(--red); border-color:var(--red); color:#fff; }
    button.red:hover { background:#ff7276; }
    button.amber { background:#39415e; border-color:#515c7e; color:#ffd796; }
    button.amber:hover { background:#465173; }
    button.icon { width:42px; padding:0; }
    button:disabled { opacity:.5; cursor:not-allowed; transform:none; }
    svg { width:17px; height:17px; flex:0 0 auto; }
    label { display:block; margin:0 0 7px; color:var(--muted); font-size:12px; font-weight:900; text-transform:uppercase; }
    input, select { width:100%; height:42px; border:1px solid #434b68; border-radius:7px; padding:0 12px; font:inherit; background:#22283c; color:var(--ink); }
    input:focus, select:focus, textarea:focus { outline:2px solid rgba(91,140,255,.24); border-color:var(--blue); }
    textarea { width:100%; min-height:320px; resize:vertical; border:1px solid #434b68; border-radius:8px; padding:14px; font:13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; background:#20263a; color:#eef2ff; }
    .fields { display:grid; grid-template-columns:1fr 112px; gap:12px; }
    .checkrow { display:flex; align-items:center; gap:8px; margin:12px 0; color:var(--ink); font-weight:800; text-transform:none; }
    .checkrow input { width:17px; height:17px; accent-color:var(--blue); }
    .server-list { display:grid; gap:10px; margin:0; padding:0; list-style:none; }
    .server-item { width:100%; text-align:left; min-height:auto; padding:13px; justify-content:flex-start; display:grid; gap:6px; border-radius:8px; background:#22283c; border:1px solid #343c58; }
    .server-item:hover { background:#28304a; }
    .server-item.active { background:#22304f; border-color:#3f6fd3; box-shadow:inset 4px 0 0 var(--blue); }
    .server-title { display:flex; justify-content:space-between; align-items:center; gap:8px; width:100%; font-weight:900; }
    .muted { color:var(--muted); font-size:13px; overflow-wrap:anywhere; }
    .pill { display:inline-flex; align-items:center; gap:7px; border:1px solid #46506d; border-radius:6px; padding:6px 10px; font-weight:900; font-size:13px; white-space:nowrap; background:#333a55; color:#dfe5ff; }
    .pill.ok { color:#9ff0bd; border-color:#397e57; background:#203d31; }
    .pill.off { color:#ffb4b7; border-color:#7a3b43; background:#442a35; }
    .server-gallery { display:grid; gap:10px; align-items:start; }
    .overview-board { display:block; }
    .server-card { width:100%; min-height:86px; padding:14px; border:1px solid #3a4260; border-radius:8px; background:#242b42; display:grid; grid-template-columns:44px minmax(0, 1fr) auto; gap:14px; text-align:left; align-items:center; }
    .server-card:hover { background:#29314b; border-color:#4a5680; }
    .server-card.active { border-color:var(--blue); box-shadow:inset 4px 0 0 var(--blue); }
    .server-icon { width:42px; height:42px; border-radius:8px; display:grid; place-items:center; background:linear-gradient(135deg, #61d18b, #2f8b57); box-shadow:0 10px 22px rgba(84,209,138,.18); }
    .server-card-main { display:grid; gap:5px; min-width:0; }
    .server-card-title { display:flex; align-items:center; gap:10px; min-width:0; }
    .server-card-title strong { font-size:17px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .server-card-meta { display:flex; flex-wrap:wrap; gap:10px; color:var(--muted); font-size:13px; font-weight:800; }
    .server-card-actions { display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end; }
    .server-card-actions button { min-height:36px; padding:0 10px; }
    .server-card-actions .danger-icon { width:36px; padding:0; color:#ff9b9f; background:transparent; border-color:#5d3b45; }
    .server-card-actions .danger-icon:hover { color:#fff; background:#7b343e; border-color:#9a404b; }
    .server-stats { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    .stat-box { min-height:54px; border-radius:7px; background:#242b42; padding:9px; }
    .stat-box span { display:block; color:var(--muted); font-size:11px; font-weight:900; text-transform:uppercase; }
    .stat-box b { display:block; margin-top:5px; font-size:14px; overflow-wrap:anywhere; }
    .grid { display:grid; grid-template-columns:repeat(4, minmax(130px, 1fr)); gap:12px; }
    .left-column .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); }
    .left-column .metric:nth-child(5) { grid-column:1 / -1; }
    .metric { border:1px solid #3a4260; border-radius:8px; padding:14px; min-height:86px; background:#242b42; }
    .metric span { display:block; color:var(--muted); font-size:12px; font-weight:900; text-transform:uppercase; }
    .metric strong { display:block; margin-top:8px; font-size:20px; font-weight:900; overflow-wrap:anywhere; }
    pre { margin:0; height:380px; overflow:auto; background:var(--code); color:#f7f8ff; padding:16px; font:13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; white-space:pre-wrap; }
    .command { flex:1 1 260px; }
    .backup-list { list-style:none; display:grid; gap:8px; padding:0; margin:0; }
    .backup-list li { border:1px solid #3a4260; border-radius:8px; padding:12px; display:grid; gap:8px; background:#242b42; }
    .row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .form-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }
    .file-layout { display:grid; grid-template-columns:minmax(240px, .75fr) minmax(360px, 1.25fr); gap:14px; }
    .file-toolbar { display:flex; gap:8px; margin-bottom:12px; }
    .file-list { display:grid; gap:8px; max-height:460px; overflow:auto; }
    .file-item { min-height:38px; justify-content:flex-start; border:1px solid #3a4260; background:#242b42; }
    .file-editor { display:grid; gap:10px; }
    .file-editor textarea { min-height:360px; }
    .dashboard { display:grid; grid-template-columns:minmax(360px, .9fr) minmax(440px, 1.25fr); gap:18px; align-items:start; }
    .left-column { display:grid; gap:18px; align-content:start; }
    .tab-panel { display:none; }
    .tab-panel.active { display:block; }
    .tab-panel.split.active { display:grid; grid-template-columns:minmax(360px, .9fr) minmax(440px, 1.25fr); gap:18px; align-items:start; }
    .toast { position:fixed; right:18px; bottom:18px; max-width:min(460px, calc(100vw - 36px)); border-radius:8px; border:1px solid #4a5576; background:#2e3654; color:#fff; padding:13px 15px; box-shadow:0 16px 40px rgba(0,0,0,.35); display:none; z-index:20; }
    .toast.error { border-color:#8c424a; background:#482a31; }
    .connection { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:13px; font-weight:800; }
    .connection-dot { width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 0 4px rgba(84,209,138,.12); }
    .connection.offline .connection-dot { background:var(--red); box-shadow:0 0 0 4px rgba(255,93,98,.12); }
    dialog.modal { width:min(520px, calc(100vw - 28px)); padding:0; color:var(--ink); background:#242936; border:1px solid #444c61; border-radius:8px; box-shadow:0 30px 80px rgba(0,0,0,.55); }
    dialog.modal::backdrop { background:rgba(8,10,14,.76); backdrop-filter:blur(3px); }
    .modal-head { min-height:62px; padding:16px 18px; display:flex; align-items:center; justify-content:space-between; gap:12px; border-bottom:1px solid rgba(255,255,255,.07); }
    .modal-body { padding:18px; display:grid; gap:16px; }
    .modal-footer { padding:14px 18px; display:flex; justify-content:flex-end; gap:8px; border-top:1px solid rgba(255,255,255,.07); background:#20242f; }
    .modal-copy { margin:0; color:#c3c9d8; line-height:1.55; }
    .form-error { min-height:20px; margin:0; color:#ff9b9f; font-size:13px; font-weight:800; }
    .empty-state { min-height:220px; display:grid; place-items:center; text-align:center; color:var(--muted); border:1px dashed #424a60; border-radius:8px; padding:28px; }
    .empty-state > div { display:grid; justify-items:center; gap:10px; }
    .empty-state svg { width:30px; height:30px; }
    @media (max-width: 1120px) { .shell { grid-template-columns:1fr; } .sidebar { position:relative; min-height:auto; max-height:none; } .dashboard, .tab-panel.split.active, .overview-board, .file-layout { grid-template-columns:1fr; } .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 620px) { .main { padding:14px; } .overview-hero, .hero { display:grid; align-items:start; } .hero .actions { justify-content:flex-start; } .tabs-nav { display:grid; overflow:auto; } .tab-list { flex-wrap:nowrap; } .grid, .left-column .grid, .fields, .server-stats, .form-grid { grid-template-columns:1fr; } .server-card { grid-template-columns:42px minmax(0, 1fr); } .server-card-actions { grid-column:1 / -1; justify-content:flex-start; } .left-column .metric:nth-child(5) { grid-column:auto; } .actions button, .actions a.button { flex:1 1 auto; } .modal-footer { display:grid; grid-template-columns:1fr 1fr; } }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark"><i data-lucide="zap"></i></span><span>BEDROCK</span></div>
      <div class="side-group">
        <h3>Menu</h3>
        <div class="nav-item active"><i data-lucide="cloud"></i>Mes serveurs</div>
      </div>
      <div class="plan-card">
        <div class="plan-title"><span class="server-icon"><i data-lucide="box"></i></span><span>Bedrock Fleet</span></div>
        <span class="muted">Multi-serveurs locaux</span>
      </div>
    </aside>

    <main class="main">
      <div class="view active" id="overviewView">
        <div class="overview-hero">
          <div>
            <h1>Mes serveurs</h1>
            <p>Choisis le serveur que tu veux gérer.</p>
          </div>
          <div class="actions">
            <button class="primary" id="openCreateServer"><i data-lucide="plus"></i>Nouveau serveur</button>
            <span id="globalPill" class="pill off"><i data-lucide="server"></i><span>...</span></span>
            <button class="icon" id="refreshServers" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
            <form method="post" action="/logout"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}"><button type="submit"><i data-lucide="log-out"></i>Sortir</button></form>
          </div>
        </div>

        <section>
          <div class="head">
            <h2>Vue d’ensemble</h2>
            <div class="connection" id="connectionStatus"><span class="connection-dot"></span><span>Panel connecté</span></div>
          </div>
          <div class="content">
            <div class="overview-board">
              <div class="server-gallery" id="serverGallery"></div>
            </div>
          </div>
        </section>
      </div>

      <div class="view" id="detailView">
      <div class="topbar">
        <button class="crumb" id="backOverview"><i data-lucide="arrow-left"></i>Mes serveurs</button>
        <div class="hero">
          <div>
            <h1 id="activeTitle">Serveur</h1>
            <div class="hero-meta">
              <span><i data-lucide="box"></i>Minecraft Bedrock</span>
              <span><i data-lucide="diamond"></i>Instance locale</span>
              <span id="activeSubtitle"><i data-lucide="wifi"></i>...</span>
            </div>
          </div>
          <div class="actions">
            <span id="statePill" class="pill off"><i data-lucide="circle"></i><span>...</span></span>
            <button class="primary" id="startBtn"><i data-lucide="play"></i>Démarrer</button>
            <button class="amber" id="restartBtn"><i data-lucide="rotate-cw"></i>Redémarrer</button>
            <button class="red" id="stopBtn"><i data-lucide="square"></i>Arrêter</button>
            <form method="post" action="/logout"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}"><button type="submit"><i data-lucide="log-out"></i>Sortir</button></form>
          </div>
        </div>
        <div class="tabs-nav">
          <div class="tab-list">
            <button class="tab active" data-tab="overview">Aperçu</button>
            <button class="tab" data-tab="console">Console</button>
            <button class="tab" data-tab="config">Configuration</button>
            <button class="tab" data-tab="backups">Sauvegardes</button>
            <button class="tab" data-tab="files">Fichiers</button>
          </div>
          <div class="actions">
            <button class="blue" id="reinstallBtn"><i data-lucide="download"></i>Réinstaller</button>
            <button class="icon" id="refreshDetail" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
          </div>
        </div>
      </div>

      <div class="tab-panel active" data-panel="overview">
        <div class="left-column">
          <section>
            <div class="head">
              <h2>Serveur</h2>
              <div class="actions">
                <button class="primary" id="saveServer"><i data-lucide="save"></i>Enregistrer</button>
                <button class="red" id="deleteServer"><i data-lucide="trash-2"></i>Supprimer</button>
              </div>
            </div>
            <div class="content">
              <div class="grid">
                <div class="metric"><span>Port</span><strong id="gamePort">...</strong></div>
                <div class="metric"><span>Adresse</span><strong id="serverAddress">...</strong></div>
                <div class="metric"><span>Monde</span><strong id="worldName">...</strong></div>
                <div class="metric"><span>Sauvegardes</span><strong id="backupCount">...</strong></div>
                <div class="metric"><span>Dossier</span><strong id="serverDir">...</strong></div>
              </div>
              <div class="fields" style="margin-top:16px">
                <div>
                  <label for="serverName">Nom</label>
                  <input id="serverName">
                </div>
                <div>
                  <label for="serverPort">Port</label>
                  <input id="serverPort" type="number" min="1" max="65534">
                </div>
              </div>
              <label class="checkrow"><input id="serverAutoStart" type="checkbox"> Auto-start</label>
            </div>
          </section>

        </div>
      </div>

      <div class="tab-panel" data-panel="console">
          <section>
            <div class="head">
              <h2>Console</h2>
              <button class="icon" id="refreshLogs" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
            </div>
            <pre id="logs"></pre>
            <div class="content">
              <div class="actions">
                <input class="command" id="commandInput" placeholder="Entrer une commande...">
                <button class="blue" id="sendCommand"><i data-lucide="send"></i>Envoyer</button>
              </div>
            </div>
          </section>
      </div>

      <div class="tab-panel" data-panel="config">
          <section>
            <div class="head">
              <h2>Configuration visuelle</h2>
              <button class="primary" id="saveProperties"><i data-lucide="save"></i>Enregistrer</button>
            </div>
            <div class="content">
              <div class="form-grid">
                <div><label for="propServerName">Nom affiché</label><input id="propServerName"></div>
                <div><label for="propLevelName">Monde</label><input id="propLevelName"></div>
                <div><label for="propGamemode">Game mode</label><select id="propGamemode"><option>survival</option><option>creative</option><option>adventure</option></select></div>
                <div><label for="propDifficulty">Difficulté</label><select id="propDifficulty"><option>peaceful</option><option>easy</option><option>normal</option><option>hard</option></select></div>
                <div><label for="propMaxPlayers">Max players</label><input id="propMaxPlayers" type="number" min="1"></div>
                <div><label for="propAllowCheats">Cheats</label><select id="propAllowCheats"><option value="false">False</option><option value="true">True</option></select></div>
                <div><label for="propOnlineMode">Mode en ligne</label><select id="propOnlineMode"><option value="true">Activé</option><option value="false">Désactivé</option></select></div>
                <div><label for="propAllowList">Liste blanche</label><select id="propAllowList"><option value="false">Désactivée</option><option value="true">Activée</option></select></div>
                <div><label for="propForceGamemode">Forcer le mode de jeu</label><select id="propForceGamemode"><option value="false">Non</option><option value="true">Oui</option></select></div>
                <div><label for="propLanVisibility">Visibilité réseau local</label><select id="propLanVisibility"><option value="false">Désactivée</option><option value="true">Activée</option></select></div>
                <div><label for="propViewDistance">Distance d’affichage</label><input id="propViewDistance" type="number" min="1"></div>
                <div><label for="propTickDistance">Distance de simulation</label><input id="propTickDistance" type="number" min="1"></div>
              </div>
            </div>
          </section>
      </div>

      <div class="tab-panel" data-panel="backups">
        <section>
          <div class="head">
            <h2>Sauvegardes</h2>
            <button class="primary" id="createBackup"><i data-lucide="archive"></i>Créer</button>
          </div>
          <div class="content">
            <ul class="backup-list" id="backupList"></ul>
          </div>
        </section>
      </div>

      <div class="tab-panel" data-panel="files">
        <section>
          <div class="head">
            <h2>Fichiers</h2>
            <div class="actions">
              <button class="primary" id="saveFile"><i data-lucide="save"></i>Enregistrer</button>
              <button class="red" id="deleteFile"><i data-lucide="trash-2"></i>Supprimer</button>
            </div>
          </div>
          <div class="content">
            <div class="file-toolbar">
              <button id="goUpFile"><i data-lucide="corner-up-left"></i>Parent</button>
              <button id="newDirectory"><i data-lucide="folder-plus"></i>Dossier</button>
              <button id="newFile"><i data-lucide="file-plus"></i>Fichier</button>
              <span class="pill" id="currentFilePath">/</span>
            </div>
            <div class="file-layout">
              <div class="file-list" id="fileList"></div>
              <div class="file-editor">
                <label for="fileEditorPath">Fichier sélectionné</label>
                <input id="fileEditorPath" readonly>
                <textarea id="fileEditor" placeholder="Sélectionne un fichier texte"></textarea>
              </div>
            </div>
          </div>
        </section>
      </div>
      </div>
    </main>
  </div>
  <dialog class="modal" id="createServerModal">
    <form id="createServerForm">
      <div class="modal-head">
        <h2>Créer un serveur</h2>
        <button class="icon" type="button" data-close-modal="createServerModal" title="Fermer"><i data-lucide="x"></i></button>
      </div>
      <div class="modal-body">
        <div>
          <label for="newName">Nom du serveur</label>
          <input id="newName" value="Nouveau serveur" maxlength="80" autocomplete="off" required>
        </div>
        <div>
          <label for="newPort">Port</label>
          <input id="newPort" type="number" min="1" max="65534" required>
        </div>
        <p class="form-error" id="createServerError"></p>
      </div>
      <div class="modal-footer">
        <button type="button" data-close-modal="createServerModal">Annuler</button>
        <button class="primary" id="createServer" type="submit"><i data-lucide="plus"></i>Créer</button>
      </div>
    </form>
  </dialog>

  <dialog class="modal" id="confirmationModal">
    <form id="confirmationForm">
      <div class="modal-head">
        <h2 id="confirmationTitle">Confirmer l’action</h2>
        <button class="icon" type="button" id="confirmationClose" title="Fermer"><i data-lucide="x"></i></button>
      </div>
      <div class="modal-body">
        <p class="modal-copy" id="confirmationMessage"></p>
        <div>
          <label for="confirmationInput" id="confirmationLabel">Confirmation</label>
          <input id="confirmationInput" autocomplete="off">
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" id="confirmationCancel">Annuler</button>
        <button class="red" id="confirmationSubmit" type="submit">Confirmer</button>
      </div>
    </form>
  </dialog>

  <dialog class="modal" id="textInputModal">
    <form id="textInputForm">
      <div class="modal-head">
        <h2 id="textInputTitle">Nouvel élément</h2>
        <button class="icon" type="button" id="textInputClose" title="Fermer"><i data-lucide="x"></i></button>
      </div>
      <div class="modal-body">
        <div>
          <label for="textInputValue" id="textInputLabel">Nom</label>
          <input id="textInputValue" autocomplete="off" required>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" id="textInputCancel">Annuler</button>
        <button class="primary" type="submit">Créer</button>
      </div>
    </form>
  </dialog>

  <div class="toast" id="toast"></div>

<script>
const $ = (id) => document.getElementById(id);
const CSRF_TOKEN = "${escapeJs(csrfToken)}";
let servers = [];
let activeId = localStorage.getItem("bedrockActiveServer") || "";
let viewMode = "overview";
let detailTab = "overview";
let busy = false;
let loadedPropertiesFor = "";
let currentFilePath = "";
let selectedFilePath = "";

async function api(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) headers["x-csrf-token"] = CSRF_TOKEN;
  let res;
  try {
    res = await fetch(path, { headers, ...options });
    setConnectionState(true);
  } catch (_error) {
    setConnectionState(false);
    throw new Error("Le panel ne répond plus. Vérifie que le service est démarré.");
  }
  if (res.status === 401) {
    window.location.assign("/login");
    throw new Error("Session expirée.");
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error || "Erreur HTTP " + res.status);
  return data;
}

function escapeHtmlClient(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function toast(message, type = "success") {
  const box = $("toast");
  box.textContent = message;
  box.className = "toast " + type;
  box.style.display = "block";
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => { box.style.display = "none"; }, 4200);
}

function setConnectionState(connected) {
  const status = $("connectionStatus");
  if (!status) return;
  status.classList.toggle("offline", !connected);
  status.querySelector("span:last-child").textContent = connected ? "Panel connecté" : "Panel hors ligne";
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll("button").forEach((button) => {
    if (button.closest("form")) return;
    button.disabled = value;
  });
}

function activeServer() {
  return servers.find((server) => server.id === activeId);
}

function endpoint(suffix) {
  return "/api/servers/" + encodeURIComponent(activeId) + suffix;
}

async function refreshServers() {
  const data = await api("/api/servers");
  servers = data.servers;
  if (activeId && !servers.some((server) => server.id === activeId)) {
    activeId = "";
    localStorage.removeItem("bedrockActiveServer");
    viewMode = "overview";
    loadedPropertiesFor = "";
  }
  if (viewMode === "detail" && !activeId) {
    viewMode = "overview";
  }
  renderGlobalPill();
  renderServerGallery();
  renderCreateDefaults();
  renderView();
  if (viewMode === "detail" && activeId) {
    await refreshActive();
  } else {
    renderActive();
  }
}

function renderGlobalPill() {
  const running = servers.filter((server) => server.status && server.status.running).length;
  $("globalPill").className = "pill " + (running ? "ok" : "off");
  $("globalPill").querySelector("span").textContent = running + "/" + servers.length + " en ligne";
}

function renderServerGallery() {
  const target = $("serverGallery");
  if (!target) return;
  target.innerHTML = servers.map((server) => {
    const status = server.status || {};
    const active = server.id === activeId ? " active" : "";
    const pill = status.running ? '<span class="pill ok">En ligne</span>' : '<span class="pill off">Arrêté</span>';
    const port = escapeHtmlClient(status.gamePort || "-");
    const world = escapeHtmlClient(status.worldName || "-");
    const address = escapeHtmlClient(serverAddress(status));
    return '<article class="server-card' + active + '" data-server-card="' + escapeHtmlClient(server.id) + '">' +
      '<span class="server-icon"><i data-lucide="box"></i></span>' +
      '<div class="server-card-main">' +
        '<div class="server-card-title"><strong>' + escapeHtmlClient(server.name) + '</strong>' + pill + '</div>' +
        '<div class="server-card-meta"><span>Port ' + port + '</span><span>' + address + '</span><span>' + world + '</span></div>' +
      '</div>' +
      '<div class="server-card-actions">' +
        '<button data-server="' + escapeHtmlClient(server.id) + '"><i data-lucide="settings"></i>Gérer</button>' +
        '<button class="danger-icon" data-delete-server="' + escapeHtmlClient(server.id) + '" title="Supprimer ' + escapeHtmlClient(server.name) + '"><i data-lucide="trash-2"></i></button>' +
      '</div>' +
    '</article>';
  }).join("") || '<div class="empty-state"><div><i data-lucide="server-off"></i><strong>Aucun serveur</strong><span>Crée ta première instance Bedrock.</span></div></div>';
  target.querySelectorAll("[data-server]").forEach((button) => {
    button.onclick = () => openServer(button.dataset.server);
  });
  target.querySelectorAll("[data-delete-server]").forEach((button) => {
    button.onclick = () => deleteServerById(button.dataset.deleteServer);
  });
  lucide.createIcons();
}

function renderView() {
  $("overviewView").classList.toggle("active", viewMode === "overview");
  $("detailView").classList.toggle("active", viewMode === "detail");
  renderTabs();
  lucide.createIcons();
}

function renderTabs() {
  document.querySelectorAll("[data-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === detailTab);
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === detailTab);
  });
}

function setDetailTab(tab) {
  detailTab = tab;
  renderTabs();
  if (tab === "console") refreshLogs().catch((error) => toast(error.message));
  if (tab === "backups") refreshBackups().catch((error) => toast(error.message));
  if (tab === "config") loadProperties().catch((error) => toast(error.message));
  if (tab === "files") loadFiles(currentFilePath).catch((error) => toast(error.message));
}

function openServer(id) {
  activeId = id;
  localStorage.setItem("bedrockActiveServer", activeId);
  loadedPropertiesFor = "";
  detailTab = "overview";
  viewMode = "detail";
  renderView();
  renderServerGallery();
  renderActive();
  refreshActive().catch((error) => toast(error.message));
}

function showOverview() {
  viewMode = "overview";
  renderView();
  refreshServers().catch((error) => toast(error.message));
}

function renderCreateDefaults() {
  const nextPort = nextFreePort();
  if (!$("newPort").value) $("newPort").value = nextPort;
}

function nextFreePort() {
  const used = servers.map((server) => Number(server.status && server.status.gamePort)).filter(Boolean);
  let port = 19132;
  while (used.includes(port)) port += 2;
  return port;
}

function renderActive() {
  const server = activeServer();
  if (!server) {
    $("activeTitle").textContent = "Aucun serveur";
    $("activeSubtitle").innerHTML = '<i data-lucide="wifi-off"></i>Aucune instance';
    $("serverName").value = "";
    $("serverPort").value = "";
    $("serverAutoStart").checked = false;
    $("statePill").className = "pill off";
    $("statePill").querySelector("span").textContent = "Aucun";
    $("gamePort").textContent = "-";
    $("worldName").textContent = "-";
    $("backupCount").textContent = "-";
    $("serverDir").textContent = "-";
    $("logs").textContent = "";
    clearPropertyForm();
    $("backupList").innerHTML = '<li><span class="muted">Aucun serveur sélectionné.</span></li>';
    $("serverAddress").textContent = "-";
  ["startBtn", "restartBtn", "stopBtn", "reinstallBtn", "saveServer", "deleteServer", "sendCommand", "createBackup", "saveProperties", "saveFile", "deleteFile"].forEach((id) => {
    $(id).disabled = true;
  });
    lucide.createIcons();
    return;
  }
  const status = server.status || {};
  $("activeTitle").textContent = server.name;
  $("activeSubtitle").innerHTML = '<i data-lucide="wifi"></i>Port ' + escapeHtmlClient(status.gamePort || "-");
  $("serverName").value = server.name;
  $("serverPort").value = status.gamePort || "";
  $("serverAutoStart").checked = Boolean(server.autoStart);
  ["startBtn", "restartBtn", "stopBtn", "reinstallBtn", "saveServer", "deleteServer", "sendCommand", "createBackup", "saveProperties", "saveFile", "deleteFile"].forEach((id) => {
    $(id).disabled = false;
  });
  $("startBtn").disabled = Boolean(status.running);
  ["restartBtn", "stopBtn", "sendCommand"].forEach((id) => {
    $(id).disabled = !status.running;
  });
  $("statePill").className = "pill " + (status.running ? "ok" : "off");
  $("statePill").querySelector("span").textContent = status.error ? "Erreur" : (status.running ? "En ligne" : "Arrêté");
  $("gamePort").textContent = status.gamePort || "-";
  $("serverAddress").textContent = serverAddress(status);
  $("worldName").textContent = status.worldName || "-";
  $("backupCount").textContent = status.backupCount ?? "-";
  $("serverDir").textContent = status.serverDir || server.serverDir || "-";
  lucide.createIcons();
}

async function refreshActive() {
  const server = activeServer();
  if (!server) {
    viewMode = "overview";
    renderView();
    renderActive();
    return;
  }
  const status = await api(endpoint("/status"));
  server.status = status;
  renderGlobalPill();
  renderServerGallery();
  renderActive();
  if (detailTab === "console") await refreshLogs();
  if (detailTab === "backups") await refreshBackups();
  if (detailTab === "config" && loadedPropertiesFor !== activeId) await loadProperties();
}

async function refreshLogs() {
  const data = await api(endpoint("/logs?limit=320"));
  $("logs").textContent = data.logs.join("");
  $("logs").scrollTop = $("logs").scrollHeight;
}

async function refreshBackups() {
  const data = await api(endpoint("/backups"));
  $("backupList").innerHTML = data.backups.map((backup) => {
    const encoded = encodeURIComponent(backup.name);
    return '<li>' +
      '<div class="row"><strong>' + escapeHtmlClient(backup.name) + '</strong><span class="muted">' + escapeHtmlClient(backup.sizeLabel) + '</span></div>' +
      '<div class="actions">' +
        '<a class="button" href="' + endpoint("/backups/") + encoded + '"><i data-lucide="download"></i>Zip</a>' +
        '<button data-restore="' + encoded + '"><i data-lucide="history"></i>Restaurer</button>' +
        '<button class="red" data-delete="' + encoded + '"><i data-lucide="trash-2"></i>Supprimer</button>' +
      '</div>' +
    '</li>';
  }).join("") || '<li><span class="muted">Aucune sauvegarde.</span></li>';
  document.querySelectorAll("[data-restore]").forEach((button) => {
    button.onclick = () => restoreBackup(decodeURIComponent(button.dataset.restore));
  });
  document.querySelectorAll("[data-delete]").forEach((button) => {
    button.onclick = () => deleteBackup(decodeURIComponent(button.dataset.delete));
  });
  lucide.createIcons();
}

async function loadProperties() {
  const data = await api(endpoint("/properties-form"));
  setPropertyForm(data.values || {});
  loadedPropertiesFor = activeId;
}

function setPropertyForm(values) {
  $("propServerName").value = values["server-name"] || "";
  $("propLevelName").value = values["level-name"] || "";
  $("propGamemode").value = values.gamemode || "survival";
  $("propDifficulty").value = values.difficulty || "easy";
  $("propMaxPlayers").value = values["max-players"] || "10";
  $("propAllowCheats").value = normalizeBool(values["allow-cheats"], "false");
  $("propOnlineMode").value = normalizeBool(values["online-mode"], "true");
  $("propAllowList").value = normalizeBool(values["allow-list"], "false");
  $("propForceGamemode").value = normalizeBool(values["force-gamemode"], "false");
  $("propLanVisibility").value = normalizeBool(values["enable-lan-visibility"], "false");
  $("propViewDistance").value = values["view-distance"] || "32";
  $("propTickDistance").value = values["tick-distance"] || "4";
}

function clearPropertyForm() {
  ["propServerName", "propLevelName", "propMaxPlayers", "propViewDistance", "propTickDistance"].forEach((id) => { $(id).value = ""; });
}

function collectPropertyForm() {
  return {
    "server-name": $("propServerName").value,
    "level-name": $("propLevelName").value,
    gamemode: $("propGamemode").value,
    difficulty: $("propDifficulty").value,
    "max-players": $("propMaxPlayers").value || "10",
    "allow-cheats": $("propAllowCheats").value,
    "online-mode": $("propOnlineMode").value,
    "allow-list": $("propAllowList").value,
    "force-gamemode": $("propForceGamemode").value,
    "enable-lan-visibility": $("propLanVisibility").value,
    "view-distance": $("propViewDistance").value || "32",
    "tick-distance": $("propTickDistance").value || "4"
  };
}

function normalizeBool(value, fallback) {
  return String(value || fallback).toLowerCase() === "true" ? "true" : "false";
}

function serverAddress(status) {
  const ip = (status.hostIps && status.hostIps[0]) || "127.0.0.1";
  return ip + ":" + (status.gamePort || "19132");
}

async function loadFiles(path = "") {
  currentFilePath = path || "";
  $("currentFilePath").textContent = "/" + currentFilePath;
  const data = await api(endpoint("/files?path=") + encodeURIComponent(currentFilePath));
  $("fileList").innerHTML = data.files.map((file) => {
    const icon = file.type === "directory" ? "folder" : "file-text";
    const info = file.type === "directory" ? "Dossier" : file.sizeLabel;
    return '<button class="file-item" data-file-type="' + file.type + '" data-file-path="' + escapeHtmlClient(file.path) + '">' +
      '<i data-lucide="' + icon + '"></i>' + escapeHtmlClient(file.name) + '<span class="muted">' + escapeHtmlClient(info) + '</span>' +
    '</button>';
  }).join("") || '<span class="muted">Dossier vide.</span>';
  document.querySelectorAll("[data-file-path]").forEach((button) => {
    button.onclick = () => {
      if (button.dataset.fileType === "directory") {
        loadFiles(button.dataset.filePath).catch((error) => toast(error.message));
      } else {
        openFile(button.dataset.filePath).catch((error) => toast(error.message));
      }
    };
  });
  lucide.createIcons();
}

async function openFile(path) {
  selectedFilePath = path;
  $("fileEditorPath").value = path;
  const data = await api(endpoint("/file?path=") + encodeURIComponent(path));
  $("fileEditor").value = data.content;
}

function parentPath(path) {
  const parts = String(path || "").split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

let confirmationResolver = null;
let textInputResolver = null;
let confirmationExpected = "";

function finishConfirmation(result) {
  if (!confirmationResolver) return;
  const resolve = confirmationResolver;
  confirmationResolver = null;
  $("confirmationModal").close();
  resolve(result);
}

function requireTypedConfirmation(message, expected, title = "Confirmer l’action") {
  confirmationExpected = expected;
  $("confirmationTitle").textContent = title;
  $("confirmationMessage").textContent = message;
  $("confirmationLabel").textContent = "Saisis « " + expected + " » pour confirmer";
  $("confirmationInput").value = "";
  $("confirmationSubmit").disabled = true;
  $("confirmationModal").showModal();
  $("confirmationInput").focus();
  return new Promise((resolve) => { confirmationResolver = resolve; });
}

function finishTextInput(value) {
  if (!textInputResolver) return;
  const resolve = textInputResolver;
  textInputResolver = null;
  $("textInputModal").close();
  resolve(value);
}

function requestTextInput(title, label) {
  $("textInputTitle").textContent = title;
  $("textInputLabel").textContent = label;
  $("textInputValue").value = "";
  $("textInputModal").showModal();
  $("textInputValue").focus();
  return new Promise((resolve) => { textInputResolver = resolve; });
}

async function deleteServerById(id) {
  const server = servers.find((item) => item.id === id);
  if (!server) return;
  if (!await requireTypedConfirmation("Le serveur, ses fichiers et ses sauvegardes seront définitivement supprimés.", server.name, "Supprimer " + server.name)) return;
  await action("Serveur supprime.", async () => {
    const previousActive = activeId;
    activeId = server.id;
    await api(endpoint(""), { method:"DELETE", body: JSON.stringify({ confirm: server.name }) });
    if (previousActive === server.id) {
      activeId = "";
      viewMode = "overview";
      localStorage.removeItem("bedrockActiveServer");
      loadedPropertiesFor = "";
    } else {
      activeId = previousActive;
    }
  }, { allowNoActive: true });
}

async function action(label, fn, options = {}) {
  if (busy || (!activeId && !options.allowNoActive)) return;
  setBusy(true);
  try {
    await fn();
    toast(label);
    await refreshServers();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    setBusy(false);
    renderActive();
  }
}

document.querySelectorAll("[data-close-modal]").forEach((button) => {
  button.onclick = () => $(button.dataset.closeModal).close();
});
$("openCreateServer").onclick = () => {
  $("createServerError").textContent = "";
  $("newPort").value = nextFreePort();
  $("createServerModal").showModal();
  $("newName").focus();
  $("newName").select();
};
$("confirmationInput").oninput = () => {
  $("confirmationSubmit").disabled = $("confirmationInput").value !== confirmationExpected;
};
$("confirmationForm").onsubmit = (event) => {
  event.preventDefault();
  if (!$("confirmationSubmit").disabled) finishConfirmation(true);
};
$("confirmationCancel").onclick = () => finishConfirmation(false);
$("confirmationClose").onclick = () => finishConfirmation(false);
$("confirmationModal").addEventListener("cancel", (event) => {
  event.preventDefault();
  finishConfirmation(false);
});
$("textInputForm").onsubmit = (event) => {
  event.preventDefault();
  const value = $("textInputValue").value.trim();
  if (value) finishTextInput(value);
};
$("textInputCancel").onclick = () => finishTextInput("");
$("textInputClose").onclick = () => finishTextInput("");
$("textInputModal").addEventListener("cancel", (event) => {
  event.preventDefault();
  finishTextInput("");
});

$("refreshServers").onclick = () => refreshServers().catch((error) => toast(error.message));
$("refreshDetail").onclick = () => refreshActive().catch((error) => toast(error.message));
$("backOverview").onclick = () => showOverview();
document.querySelectorAll("[data-tab]").forEach((button) => {
  button.onclick = () => setDetailTab(button.dataset.tab);
});
$("refreshLogs").onclick = () => refreshLogs().catch((error) => toast(error.message));
$("startBtn").onclick = () => action("Serveur démarré.", () => api(endpoint("/start"), { method:"POST" }));
$("stopBtn").onclick = () => action("Serveur arrêté.", () => api(endpoint("/stop"), { method:"POST" }));
$("restartBtn").onclick = () => action("Serveur redémarré.", () => api(endpoint("/restart"), { method:"POST" }));
$("reinstallBtn").onclick = async () => {
  if (!await requireTypedConfirmation("Une sauvegarde sera créée avant de réinstaller les fichiers du serveur.", "REINSTALL", "Réinstaller le serveur")) return;
  action("Reinstallation terminee.", () => api(endpoint("/reinstall"), { method:"POST", body: JSON.stringify({ confirm: "REINSTALL" }) }));
};
$("sendCommand").onclick = () => {
  const command = $("commandInput").value.trim();
  if (!command) return;
  action("Commande envoyée.", () => api(endpoint("/command"), { method:"POST", body: JSON.stringify({ command }) }));
  $("commandInput").value = "";
};
$("commandInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("sendCommand").click();
});
$("createBackup").onclick = () => action("Sauvegarde créée.", () => api(endpoint("/backups"), { method:"POST" }));
$("saveProperties").onclick = () => action("Configuration enregistrée.", () => api(endpoint("/properties-form"), { method:"PUT", body: JSON.stringify({ values: collectPropertyForm() }) }));
$("saveServer").onclick = () => action("Serveur modifié.", () => api(endpoint(""), {
  method:"PATCH",
  body: JSON.stringify({
    name: $("serverName").value,
    port: $("serverPort").value,
    autoStart: $("serverAutoStart").checked
  })
}));
$("deleteServer").onclick = () => {
  const server = activeServer();
  if (!server) return;
  deleteServerById(server.id);
};

$("createServerForm").onsubmit = (event) => {
  event.preventDefault();
  const name = $("newName").value.trim();
  const port = Number($("newPort").value);
  if (!name) {
    $("createServerError").textContent = "Le nom du serveur est obligatoire.";
    return;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65534) {
    $("createServerError").textContent = "Choisis un port compris entre 1 et 65534.";
    return;
  }
  $("createServerError").textContent = "";
  action("Serveur créé.", async () => {
    const data = await api("/api/servers", {
      method:"POST",
      body: JSON.stringify({
        name,
        port
      })
    });
    $("createServerModal").close();
    activeId = data.server.id;
    localStorage.setItem("bedrockActiveServer", activeId);
    viewMode = "detail";
    loadedPropertiesFor = "";
    $("newName").value = "Nouveau serveur";
    $("newPort").value = "";
  }, { allowNoActive: true });
};

$("goUpFile").onclick = () => loadFiles(parentPath(currentFilePath)).catch((error) => toast(error.message));
$("newDirectory").onclick = async () => {
  const name = await requestTextInput("Nouveau dossier", "Nom du dossier");
  if (!name) return;
  const target = [currentFilePath, name].filter(Boolean).join("/");
  action("Dossier créé.", () => api(endpoint("/directory"), { method:"POST", body: JSON.stringify({ path: target }) }).then(() => loadFiles(currentFilePath)));
};
$("newFile").onclick = async () => {
  const name = await requestTextInput("Nouveau fichier", "Nom du fichier");
  if (!name) return;
  const target = [currentFilePath, name].filter(Boolean).join("/");
  action("Fichier créé.", () => api(endpoint("/file"), { method:"PUT", body: JSON.stringify({ path: target, content: "" }) }).then(() => loadFiles(currentFilePath)));
};
$("saveFile").onclick = () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.");
  action("Fichier enregistré.", () => api(endpoint("/file"), { method:"PUT", body: JSON.stringify({ path: selectedFilePath, content: $("fileEditor").value }) }));
};
$("deleteFile").onclick = async () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.");
  if (!await requireTypedConfirmation("Le fichier sera définitivement supprimé.", selectedFilePath, "Supprimer le fichier")) return;
  action("Fichier supprime.", () => api(endpoint("/file?path=") + encodeURIComponent(selectedFilePath), { method:"DELETE", body: JSON.stringify({ confirm: selectedFilePath }) }).then(() => {
    selectedFilePath = "";
    $("fileEditorPath").value = "";
    $("fileEditor").value = "";
    return loadFiles(currentFilePath);
  }));
};

window.restoreBackup = async (name) => {
  if (!await requireTypedConfirmation("Le serveur sera arrêté pendant la restauration de " + name + ".", "RESTORE", "Restaurer la sauvegarde")) return;
  action("Sauvegarde restauree.", () => api(endpoint("/backups/") + encodeURIComponent(name) + "/restore", { method:"POST", body: JSON.stringify({ confirm: "RESTORE" }) }));
};
window.deleteBackup = async (name) => {
  if (!await requireTypedConfirmation("La sauvegarde sera définitivement supprimée.", name, "Supprimer la sauvegarde")) return;
  action("Sauvegarde supprimee.", () => api(endpoint("/backups/") + encodeURIComponent(name), { method:"DELETE", body: JSON.stringify({ confirm: name }) }));
};

lucide.createIcons();
refreshServers().catch((error) => toast(error.message));
setInterval(() => {
  if (viewMode === "detail" && activeId) {
    refreshActive().catch(() => {});
  } else {
    refreshServers().catch(() => {});
  }
}, 5000);
</script>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeCompare(left, right) {
  const leftHash = crypto.createHash("sha256").update(String(left)).digest();
  const rightHash = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function escapeJs(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("</", "<\\/");
}

function requireConfirmation(req, expected) {
  const provided = String(req.body?.confirm || "");
  if (!expected || !safeCompare(provided, expected)) {
    throw httpError(400, "Confirmation requise.");
  }
}

function normalizePropertyPatch(values) {
  return {
    "server-name": cleanText(values["server-name"], 80, "Dedicated Server"),
    "level-name": cleanText(values["level-name"], 80, "Bedrock level"),
    gamemode: enumValue(values.gamemode, ["survival", "creative", "adventure"], "survival"),
    difficulty: enumValue(values.difficulty, ["peaceful", "easy", "normal", "hard"], "easy"),
    "max-players": String(clampInt(values["max-players"], 1, 1000, 10)),
    "allow-cheats": boolText(values["allow-cheats"], "false"),
    "online-mode": boolText(values["online-mode"], "true"),
    "allow-list": boolText(values["allow-list"], "false"),
    "force-gamemode": boolText(values["force-gamemode"], "false"),
    "enable-lan-visibility": boolText(values["enable-lan-visibility"], "false"),
    "view-distance": String(clampInt(values["view-distance"], 2, 96, 32)),
    "tick-distance": String(clampInt(values["tick-distance"], 2, 12, 4))
  };
}

function cleanText(value, maxLength, fallback) {
  const text = String(value || "").replace(/[\r\n]/g, " ").trim().slice(0, maxLength);
  return text || fallback;
}

function enumValue(value, allowed, fallback) {
  const text = String(value || "").toLowerCase();
  return allowed.includes(text) ? text : fallback;
}

function boolText(value, fallback) {
  return String(value || fallback).toLowerCase() === "true" ? "true" : "false";
}

function clampInt(value, min, max, fallback) {
  const number = Number.parseInt(value, 10);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function defaultSessionDir(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/panel/sessions";
  }
  return path.join(rootDir, ".panel", "sessions");
}

function isLoginLimited(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAt > LOGIN_WINDOW_MS) {
    loginFailures.delete(ip);
    return false;
  }
  return entry.count >= MAX_LOGIN_FAILURES;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const entry = loginFailures.get(ip);
  if (!entry || now - entry.firstAt > LOGIN_WINDOW_MS) {
    loginFailures.set(ip, { count: 1, firstAt: now });
    return;
  }
  entry.count += 1;
}

function clearFailedLogins(ip) {
  loginFailures.delete(ip);
}

function parseProperties(content) {
  const values = {};
  for (const line of String(content || "").split(/\r?\n/)) {
    if (!line || line.trim().startsWith("#") || !line.includes("=")) continue;
    const index = line.indexOf("=");
    values[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return values;
}

function mergeProperties(content, patch) {
  const values = {};
  for (const [key, value] of Object.entries(patch)) {
    values[key] = String(value);
  }
  const seen = new Set();
  const lines = String(content || "").split(/\r?\n/).map((line) => {
    if (!line || line.trim().startsWith("#") || !line.includes("=")) return line;
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    if (!(key in values)) return line;
    seen.add(key);
    return `${key}=${values[key]}`;
  });
  for (const [key, value] of Object.entries(values)) {
    if (!seen.has(key)) lines.push(`${key}=${value}`);
  }
  return lines.join("\n");
}
