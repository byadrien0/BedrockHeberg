import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MultiServerManager } from "./multi-server-manager.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const adminPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(12).toString("base64url");
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
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
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);

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

app.get("/", requireAuth, (_req, res) => {
  res.type("html").send(panelHtml());
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
  await manager.writeProperties(mergeProperties(current, req.body.values || {}));
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
  await serverFrom(req).deleteFile(String(req.query.path || ""));
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
  await serverFrom(req).restoreBackup(req.params.name);
  res.json({ ok: true });
}));

app.delete("/api/servers/:id/backups/:name", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).deleteBackup(req.params.name);
  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Erreur serveur" });
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

function panelHtml() {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bedrock Host Panel</title>
  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
  <style>
    :root { --ink:#f7f8ff; --muted:#a8afc9; --bg:#111522; --panel:#272c42; --panel-2:#303650; --panel-3:#1c2234; --line:#394059; --blue:#5b8cff; --blue-2:#223763; --red:#ff5d62; --green:#54d18a; --amber:#f2b85b; --code:#111521; --soft:#202842; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:radial-gradient(circle at 80% 0%, rgba(91,140,255,.18), transparent 34%), var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; letter-spacing:0; }
    body::before { content:""; position:fixed; inset:0; pointer-events:none; background:linear-gradient(90deg, rgba(15,18,30,.92) 0 310px, rgba(17,21,34,.68)), url("https://images.unsplash.com/photo-1607513746994-51f730a44832?auto=format&fit=crop&w=1800&q=70"); background-size:cover; background-position:center; opacity:.22; }
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
    .overview-hero { min-height:120px; display:flex; align-items:flex-end; justify-content:space-between; gap:18px; padding:6px 0 0; }
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
    .server-gallery { display:grid; grid-template-columns:repeat(auto-fill, minmax(260px, 1fr)); gap:14px; align-items:stretch; }
    .overview-board { display:grid; grid-template-columns:minmax(0, 1fr) minmax(280px, 340px); gap:14px; align-items:start; }
    .create-card { min-height:132px; border:1px solid #3a4260; border-radius:8px; background:#2c334d; padding:16px; display:grid; gap:12px; }
    .create-card .fields { grid-template-columns:1fr 112px; }
    .server-card { width:100%; min-height:132px; padding:16px; border:1px solid #3a4260; border-radius:8px; background:linear-gradient(135deg, rgba(47,55,84,.94), rgba(36,42,64,.94)); display:grid; gap:12px; text-align:left; align-content:start; }
    .server-card.active { border-color:var(--blue); box-shadow:0 0 0 2px rgba(91,140,255,.18), inset 0 3px 0 var(--blue); }
    .server-card-top { display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .server-icon { width:44px; height:44px; border-radius:8px; display:grid; place-items:center; background:linear-gradient(135deg, #61d18b, #2f8b57); box-shadow:0 10px 22px rgba(84,209,138,.18); }
    .server-card strong { font-size:17px; }
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
    .resource-grid { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; margin-top:16px; }
    .file-layout { display:grid; grid-template-columns:minmax(240px, .75fr) minmax(360px, 1.25fr); gap:14px; }
    .file-toolbar { display:flex; gap:8px; margin-bottom:12px; }
    .file-list { display:grid; gap:8px; max-height:460px; overflow:auto; }
    .file-item { min-height:38px; justify-content:flex-start; border:1px solid #3a4260; background:#242b42; }
    .file-editor { display:grid; gap:10px; }
    .file-editor textarea { min-height:360px; }
    .dashboard { display:grid; grid-template-columns:minmax(360px, .9fr) minmax(440px, 1.25fr); gap:18px; align-items:start; }
    .left-column, .right-column { display:grid; gap:18px; align-content:start; }
    .tab-panel { display:none; }
    .tab-panel.active { display:block; }
    .tab-panel.split.active { display:grid; grid-template-columns:minmax(360px, .9fr) minmax(440px, 1.25fr); gap:18px; align-items:start; }
    .toast { position:fixed; right:18px; bottom:18px; max-width:min(460px, calc(100vw - 36px)); border-radius:8px; border:1px solid #4a5576; background:#2e3654; color:#fff; padding:13px 15px; box-shadow:0 16px 40px rgba(0,0,0,.35); display:none; z-index:5; }
    @media (max-width: 1120px) { .shell { grid-template-columns:1fr; } .sidebar { position:relative; min-height:auto; max-height:none; } .dashboard, .tab-panel.split.active, .overview-board, .file-layout { grid-template-columns:1fr; } .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 620px) { .main { padding:14px; } .hero { display:grid; } .hero .actions { justify-content:flex-start; } .tabs-nav { display:grid; } .grid, .left-column .grid, .fields, .create-card .fields, .server-stats, .form-grid, .resource-grid { grid-template-columns:1fr; } .left-column .metric:nth-child(5) { grid-column:auto; } .actions button, .actions a.button { flex:1 1 auto; } }
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
            <span id="globalPill" class="pill off"><i data-lucide="server"></i><span>...</span></span>
            <button class="icon" id="refreshServers" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
            <form method="post" action="/logout"><button type="submit"><i data-lucide="log-out"></i>Sortir</button></form>
          </div>
        </div>

        <section>
          <div class="head">
            <h2>Vue d’ensemble</h2>
            <span class="muted">Tous tes serveurs</span>
          </div>
          <div class="content">
            <div class="overview-board">
              <div class="server-gallery" id="serverGallery"></div>
              <div class="create-card">
                <h2>Créer un serveur</h2>
                <div class="fields">
                  <div>
                    <label for="newName">Nom</label>
                    <input id="newName" value="Nouveau serveur">
                  </div>
                  <div>
                    <label for="newPort">Port</label>
                    <input id="newPort" type="number" min="1" max="65534">
                  </div>
                </div>
                <div>
                  <label for="templateServer">Template</label>
                  <select id="templateServer"></select>
                </div>
                <label class="checkrow"><input id="newAutoStart" type="checkbox"> Auto-start</label>
                <button class="primary" id="createServer"><i data-lucide="plus"></i>Créer</button>
              </div>
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
            <button class="red" id="stopBtn"><i data-lucide="square"></i>Stop</button>
            <form method="post" action="/logout"><button type="submit"><i data-lucide="log-out"></i>Sortir</button></form>
          </div>
        </div>
        <div class="tabs-nav">
          <div class="tab-list">
            <button class="tab active" data-tab="overview">Overview</button>
            <button class="tab" data-tab="console">Console</button>
            <button class="tab" data-tab="config">Config</button>
            <button class="tab" data-tab="backups">Backups</button>
            <button class="tab" data-tab="files">Files</button>
          </div>
          <div class="actions">
            <button class="blue" id="reinstallBtn"><i data-lucide="download"></i>Réinstaller</button>
            <button class="icon" id="refreshDetail" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
          </div>
        </div>
      </div>

      <div class="tab-panel split active" data-panel="overview">
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
              <h3 style="margin-top:16px">Ressources prévues</h3>
              <div class="resource-grid">
                <div>
                  <label for="resourceRam">RAM MB</label>
                  <input id="resourceRam" type="number" min="256" step="256">
                </div>
                <div>
                  <label for="resourceCpu">CPU cores</label>
                  <input id="resourceCpu" type="number" min="0.25" step="0.25">
                </div>
                <div>
                  <label for="resourceStorage">Stockage GB</label>
                  <input id="resourceStorage" type="number" min="1" step="1">
                </div>
              </div>
            </div>
          </section>

        </div>

        <div class="right-column">
          <section>
            <div class="head">
              <h2>Actions rapides</h2>
            </div>
            <div class="content">
              <div class="actions">
                <button class="primary" id="overviewStartBtn"><i data-lucide="play"></i>Démarrer</button>
                <button class="amber" id="overviewRestartBtn"><i data-lucide="rotate-cw"></i>Redémarrer</button>
                <button class="red" id="overviewStopBtn"><i data-lucide="square"></i>Stop</button>
              </div>
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
                <div><label for="propOnlineMode">Online mode</label><select id="propOnlineMode"><option value="true">True</option><option value="false">False</option></select></div>
                <div><label for="propAllowList">Allow list</label><select id="propAllowList"><option value="false">False</option><option value="true">True</option></select></div>
                <div><label for="propForceGamemode">Force gamemode</label><select id="propForceGamemode"><option value="false">False</option><option value="true">True</option></select></div>
                <div><label for="propLanVisibility">LAN visibility</label><select id="propLanVisibility"><option value="false">False</option><option value="true">True</option></select></div>
                <div><label for="propViewDistance">View distance</label><input id="propViewDistance" type="number" min="1"></div>
                <div><label for="propTickDistance">Tick distance</label><input id="propTickDistance" type="number" min="1"></div>
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
            <h2>Files</h2>
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
  <div class="toast" id="toast"></div>

<script>
const $ = (id) => document.getElementById(id);
let servers = [];
let activeId = localStorage.getItem("bedrockActiveServer") || "";
let viewMode = "overview";
let detailTab = "overview";
let busy = false;
let loadedPropertiesFor = "";
let currentFilePath = "";
let selectedFilePath = "";

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
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

function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.style.display = "block";
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => { box.style.display = "none"; }, 4200);
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
  renderTemplateOptions();
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
    const pill = status.running ? '<span class="pill ok">Online</span>' : '<span class="pill off">Offline</span>';
    return '<button class="server-card' + active + '" data-server="' + escapeHtmlClient(server.id) + '">' +
      '<span class="server-card-top">' +
        '<span class="server-icon"><i data-lucide="box"></i></span>' +
        pill +
      '</span>' +
      '<strong>' + escapeHtmlClient(server.name) + '</strong>' +
      '<span class="muted">Cliquer pour gérer</span>' +
    '</button>';
  }).join("") || '<div class="muted">Aucun serveur.</div>';
  target.querySelectorAll("[data-server]").forEach((button) => {
    button.onclick = () => openServer(button.dataset.server);
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

function renderTemplateOptions() {
  $("templateServer").innerHTML = servers.map((server) =>
    '<option value="' + escapeHtmlClient(server.id) + '">' + escapeHtmlClient(server.name) + '</option>'
  ).join("");
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
    ["overviewStartBtn", "overviewRestartBtn", "overviewStopBtn"].forEach((id) => {
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
  $("resourceRam").value = server.resources?.ramMb || 2048;
  $("resourceCpu").value = server.resources?.cpuCores || 1;
  $("resourceStorage").value = server.resources?.storageGb || 5;
  ["startBtn", "restartBtn", "stopBtn", "reinstallBtn", "saveServer", "deleteServer", "sendCommand", "createBackup", "saveProperties", "saveFile", "deleteFile"].forEach((id) => {
    $(id).disabled = false;
  });
  ["overviewStartBtn", "overviewRestartBtn", "overviewStopBtn"].forEach((id) => {
    $(id).disabled = false;
  });
  $("statePill").className = "pill " + (status.running ? "ok" : "off");
  $("statePill").querySelector("span").textContent = status.running ? "En ligne" : "Arrêté";
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
  await refreshLogs();
  await refreshBackups();
  if (loadedPropertiesFor !== activeId) await loadProperties();
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

async function action(label, fn, options = {}) {
  if (busy || (!activeId && !options.allowNoActive)) return;
  setBusy(true);
  try {
    await fn();
    toast(label);
    await refreshServers();
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
    renderActive();
  }
}

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
$("overviewStartBtn").onclick = () => action("Serveur démarré.", () => api(endpoint("/start"), { method:"POST" }));
$("overviewStopBtn").onclick = () => action("Serveur arrêté.", () => api(endpoint("/stop"), { method:"POST" }));
$("overviewRestartBtn").onclick = () => action("Serveur redémarré.", () => api(endpoint("/restart"), { method:"POST" }));
$("reinstallBtn").onclick = () => {
  if (!confirm("Réinstaller ce serveur et créer une sauvegarde avant ?")) return;
  action("Réinstallation terminée.", () => api(endpoint("/reinstall"), { method:"POST" }));
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
    autoStart: $("serverAutoStart").checked,
    resources: {
      ramMb: $("resourceRam").value,
      cpuCores: $("resourceCpu").value,
      storageGb: $("resourceStorage").value
    }
  })
}));
$("deleteServer").onclick = () => {
  const server = activeServer();
  if (!server) return;
  if (!confirm("Supprimer " + server.name + " avec ses fichiers et sauvegardes ?")) return;
  action("Serveur supprimé.", async () => {
    await api(endpoint(""), { method:"DELETE" });
    activeId = "";
    viewMode = "overview";
    localStorage.removeItem("bedrockActiveServer");
    loadedPropertiesFor = "";
  });
};
$("createServer").onclick = () => {
  action("Serveur créé.", async () => {
    const data = await api("/api/servers", {
      method:"POST",
      body: JSON.stringify({
        name: $("newName").value,
        port: $("newPort").value,
        autoStart: $("newAutoStart").checked,
        templateServerId: $("templateServer").value
      })
    });
    activeId = data.server.id;
    localStorage.setItem("bedrockActiveServer", activeId);
    viewMode = "detail";
    loadedPropertiesFor = "";
    $("newName").value = "Nouveau serveur";
    $("newPort").value = "";
  }, { allowNoActive: true });
};

$("goUpFile").onclick = () => loadFiles(parentPath(currentFilePath)).catch((error) => toast(error.message));
$("newDirectory").onclick = () => {
  const name = prompt("Nom du dossier");
  if (!name) return;
  const target = [currentFilePath, name].filter(Boolean).join("/");
  action("Dossier créé.", () => api(endpoint("/directory"), { method:"POST", body: JSON.stringify({ path: target }) }).then(() => loadFiles(currentFilePath)));
};
$("newFile").onclick = () => {
  const name = prompt("Nom du fichier");
  if (!name) return;
  const target = [currentFilePath, name].filter(Boolean).join("/");
  action("Fichier créé.", () => api(endpoint("/file"), { method:"PUT", body: JSON.stringify({ path: target, content: "" }) }).then(() => loadFiles(currentFilePath)));
};
$("saveFile").onclick = () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.");
  action("Fichier enregistré.", () => api(endpoint("/file"), { method:"PUT", body: JSON.stringify({ path: selectedFilePath, content: $("fileEditor").value }) }));
};
$("deleteFile").onclick = () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.");
  if (!confirm("Supprimer " + selectedFilePath + " ?")) return;
  action("Fichier supprimé.", () => api(endpoint("/file?path=") + encodeURIComponent(selectedFilePath), { method:"DELETE" }).then(() => {
    selectedFilePath = "";
    $("fileEditorPath").value = "";
    $("fileEditor").value = "";
    return loadFiles(currentFilePath);
  }));
};

window.restoreBackup = (name) => {
  if (!confirm("Restaurer " + name + " ? Le serveur sera arrêté pendant la restauration.")) return;
  action("Sauvegarde restaurée.", () => api(endpoint("/backups/") + encodeURIComponent(name) + "/restore", { method:"POST" }));
};
window.deleteBackup = (name) => {
  if (!confirm("Supprimer " + name + " ?")) return;
  action("Sauvegarde supprimée.", () => api(endpoint("/backups/") + encodeURIComponent(name), { method:"DELETE" }));
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
