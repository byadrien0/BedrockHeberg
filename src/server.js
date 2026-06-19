import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import multer from "multer";
import { MultiServerManager } from "./multi-server-manager.js";
import { ActivityStore } from "./activity-store.js";
import { UserStore } from "./user-store.js";
import { PlayitManager } from "./playit-manager.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const port = Number(process.env.PORT || 3001);
const sessionDir = path.resolve(process.env.SESSION_DIR || defaultSessionDir(rootDir));
const runtimeSecrets = await loadOrCreateRuntimeSecrets(path.join(path.dirname(sessionDir), "runtime-secrets.json"));
const adminPassword = process.env.ADMIN_PASSWORD || runtimeSecrets.adminPassword;
const sessionSecret = process.env.SESSION_SECRET || runtimeSecrets.sessionSecret;
const usingGeneratedPassword = !process.env.ADMIN_PASSWORD;
const loginFailures = new Map();
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const MAX_LOGIN_FAILURES = 8;
const activity = new ActivityStore(path.join(path.dirname(sessionDir), "activity.json"));
await activity.initialize();
const users = new UserStore(path.join(path.dirname(sessionDir), "users.json"));
await users.initialize(adminPassword, { resetSoleAdminPassword:usingGeneratedPassword && runtimeSecrets.created });
const playit = new PlayitManager({
  secret:process.env.PLAYIT_SECRET || process.env.SECRET_KEY,
  address:process.env.PLAYIT_ADDRESS,
  binary:process.env.PLAYIT_BIN
});
playit.start();
const upload = multer({ dest: path.join(os.tmpdir(), "bedrock-panel-uploads"), limits: { fileSize: 1024 * 1024 * 1024 } });

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
  autoStart: process.env.AUTO_START !== "false",
  onActivity: (entry) => activity.add(entry)
});

await fleet.initialize();
fleet.startBackupScheduler();

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
app.get("/health", (_req, res) => {
  res.json({ ok:true, playit:playit.status().state });
});
app.use("/api", (req, res, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && req.session?.authenticated && (req.session.user?.role || "admin") !== "admin") {
    return res.status(403).json({ error: "Action réservée aux administrateurs." });
  }
  next();
});

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

async function trackedOperation(req, actionName, operationType, task) {
  const manager = serverFrom(req);
  try {
    const result = await manager.runOperation(operationType, (reportProgress) => task(manager, reportProgress));
    await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: actionName, message: "Terminé" });
    return result;
  } catch (error) {
    await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: actionName, status: "error", message: error.message });
    throw error;
  }
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

app.post("/login", asyncRoute(async (req, res) => {
  if (isLoginLimited(req.ip)) {
    return res.status(429).type("html").send(loginHtml("Trop de tentatives. Reessaie dans quelques minutes."));
  }
  const user = await users.authenticate(req.body.username || "admin", req.body.password, req.body.token);
  if (!user || user.requiresTotp) {
    recordFailedLogin(req.ip);
    const error = user?.requiresTotp ? "Code d'authentification requis ou invalide." : "Identifiants incorrects.";
    return res.status(401).type("html").send(loginHtml(error));
  }
  clearFailedLogins(req.ip);
  req.session.authenticated = true;
  req.session.user = user;
  res.redirect("/");
}));

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
  await activity.add({ serverId: server.id, user: req.session.user?.username || "admin", action: "server.create", message: server.name });
  res.status(201).json({ ok: true, server });
}));

app.patch("/api/servers/:id", requireAuth, asyncRoute(async (req, res) => {
  const server = await fleet.update(req.params.id, {
    name: req.body.name,
    port: req.body.port,
    autoStart: req.body.autoStart,
    resources: req.body.resources,
    backupPolicy: req.body.backupPolicy
  });
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "server.update", message: server.name });
  res.json({ ok: true, server });
}));

app.delete("/api/servers/:id", requireAuth, asyncRoute(async (req, res) => {
  const server = fleet.require(req.params.id).meta;
  requireConfirmation(req, server.name);
  await fleet.delete(req.params.id);
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "server.delete", message: server.name });
  res.json({ ok: true });
}));

app.get("/api/servers/:id/status", requireAuth, asyncRoute(async (req, res) => {
  res.json({ ...(await serverFrom(req).status()), playit:playit.status() });
}));

app.get("/api/servers/:id/logs", requireAuth, (req, res) => {
  res.json({ logs: serverFrom(req).logs(Number(req.query.limit || 300)) });
});

app.get("/api/servers/:id/events", requireAuth, (req, res) => {
  const manager = serverFrom(req);
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();
  const send = (event) => res.write(`event: ${event.type === "error" ? "operation-error" : event.type}\ndata: ${JSON.stringify({ ...event.data, at: event.at })}\n\n`);
  res.write(`event: ready\ndata: ${JSON.stringify({ logs: manager.logs(400), operation: manager.operation })}\n\n`);
  const unsubscribe = manager.subscribe(send);
  const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 15000);
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

app.get("/api/servers/:id/commands", requireAuth, (req, res) => {
  res.json({ commands: serverFrom(req).recentCommands() });
});

app.post("/api/servers/:id/start", requireAuth, asyncRoute(async (req, res) => {
  await trackedOperation(req, "server.start", "starting", (manager) => manager.start());
  res.json({ ok: true });
}));

app.post("/api/servers/:id/stop", requireAuth, asyncRoute(async (req, res) => {
  await trackedOperation(req, "server.stop", "stopping", (manager) => manager.stop());
  res.json({ ok: true });
}));

app.post("/api/servers/:id/restart", requireAuth, asyncRoute(async (req, res) => {
  await trackedOperation(req, "server.restart", "restarting", (manager) => manager.restart());
  res.json({ ok: true });
}));

app.post("/api/servers/:id/reinstall", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, "REINSTALL");
  const result = await trackedOperation(req, "server.update", "updating", (manager, progress) => manager.reinstall(progress));
  res.json({ ok: true, ...result });
}));

app.post("/api/servers/:id/install", requireAuth, asyncRoute(async (req, res) => {
  const status = await trackedOperation(req, "server.install", "installing", async (manager, progress) => {
    await manager.installBedrock(false, progress);
    return manager.status();
  });
  res.json({ ok: true, status });
}));

app.get("/api/servers/:id/version", requireAuth, asyncRoute(async (req, res) => {
  res.json(await serverFrom(req).latestVersionInfo());
}));

app.post("/api/servers/:id/binary", requireAuth, upload.single("file"), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier binaire manquant." });
  try {
    const manager = serverFrom(req);
    const expected = process.platform === "win32" ? "bedrock_server.exe" : "bedrock_server";
    if (path.basename(req.file.originalname).toLowerCase() !== expected.toLowerCase()) {
      return res.status(400).json({ error: `Le fichier doit s'appeler ${expected}.` });
    }
    await trackedOperation(req, "server.binary.upload", "installing", async (_manager, progress) => {
      progress(20);
      await fsp.mkdir(manager.serverDir, { recursive: true });
      await fsp.copyFile(req.file.path, manager.executablePath());
      await fsp.chmod(manager.executablePath(), 0o755).catch(() => {});
      progress(100);
    });
    res.json({ ok: true, status: await manager.status() });
  } finally {
    await fsp.rm(req.file.path, { force: true }).catch(() => {});
  }
}));

app.post("/api/servers/:id/command", requireAuth, asyncRoute(async (req, res) => {
  const command = String(req.body.command || "").trim();
  if (!command) return res.status(400).json({ error: "Commande vide" });
  serverFrom(req).sendCommand(command);
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "console.command", message: command });
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
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "configuration.update", message: "server.properties" });
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
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "file.write", message: String(req.body.path || "") });
  res.json({ ok: true });
}));

app.post("/api/servers/:id/directory", requireAuth, asyncRoute(async (req, res) => {
  await serverFrom(req).makeDirectory(String(req.body.path || ""));
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "directory.create", message: String(req.body.path || "") });
  res.json({ ok: true });
}));

app.delete("/api/servers/:id/file", requireAuth, asyncRoute(async (req, res) => {
  const target = String(req.query.path || "");
  requireConfirmation(req, target);
  await serverFrom(req).deleteFile(target);
  await activity.add({ serverId: req.params.id, user: req.session.user?.username || "admin", action: "file.delete", message: target });
  res.json({ ok: true });
}));

app.get("/api/servers/:id/backups", requireAuth, asyncRoute(async (req, res) => {
  res.json({ backups: await serverFrom(req).listBackups() });
}));

app.post("/api/servers/:id/backups", requireAuth, asyncRoute(async (req, res) => {
  const backup = await trackedOperation(req, "backup.create", "backing-up", (manager) => manager.createBackup("manual"));
  res.json({ ok: true, backup });
}));

app.get("/api/servers/:id/backups/:name", requireAuth, asyncRoute(async (req, res) => {
  const file = await serverFrom(req).resolveBackup(req.params.name);
  res.download(file);
}));

app.post("/api/servers/:id/backups/:name/restore", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, "RESTORE");
  await trackedOperation(req, "backup.restore", "restoring", (manager) => manager.restoreBackup(req.params.name));
  res.json({ ok: true });
}));

app.delete("/api/servers/:id/backups/:name", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, req.params.name);
  await trackedOperation(req, "backup.delete", "deleting-backup", (manager) => manager.deleteBackup(req.params.name));
  res.json({ ok: true });
}));

app.get("/api/servers/:id/players", requireAuth, asyncRoute(async (req, res) => {
  const manager = serverFrom(req);
  const [players, allowlist, permissions] = await Promise.all([
    manager.listPlayers(),
    manager.allowlist(),
    manager.permissions()
  ]);
  res.json({ players, allowlist, permissions });
}));

app.post("/api/servers/:id/players/:name/kick", requireAuth, asyncRoute(async (req, res) => {
  serverFrom(req).kickPlayer(req.params.name, req.body.reason);
  await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: "player.kick", message: req.params.name });
  res.json({ ok: true });
}));

app.put("/api/servers/:id/allowlist", requireAuth, asyncRoute(async (req, res) => {
  const allowlist = await serverFrom(req).saveAllowlist(req.body.entries);
  await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: "allowlist.update", message: `${allowlist.length} entrée(s)` });
  res.json({ ok: true, allowlist });
}));

app.put("/api/servers/:id/permissions", requireAuth, asyncRoute(async (req, res) => {
  const permissions = await serverFrom(req).savePermissions(req.body.entries);
  await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: "permissions.update", message: `${permissions.length} entrée(s)` });
  res.json({ ok: true, permissions });
}));

app.get("/api/servers/:id/worlds", requireAuth, asyncRoute(async (req, res) => {
  res.json({ worlds: await serverFrom(req).listWorlds() });
}));

app.post("/api/servers/:id/worlds/import", requireAuth, upload.single("file"), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier .mcworld manquant." });
  try {
    if (path.extname(req.file.originalname).toLowerCase() !== ".mcworld") return res.status(400).json({ error: "Le fichier doit être au format .mcworld." });
    const world = await trackedOperation(req, "world.import", "importing-world", (manager) => manager.importWorld(req.file.path, req.file.originalname));
    res.status(201).json({ ok: true, world });
  } finally {
    await fsp.rm(req.file.path, { force: true }).catch(() => {});
  }
}));

app.get("/api/servers/:id/worlds/:name/download", requireAuth, asyncRoute(async (req, res) => {
  const target = path.join(os.tmpdir(), `bedrock-world-${crypto.randomBytes(6).toString("hex")}.mcworld`);
  await serverFrom(req).exportWorld(req.params.name, target);
  res.download(target, `${req.params.name}.mcworld`, () => fsp.rm(target, { force: true }).catch(() => {}));
}));

app.post("/api/servers/:id/worlds/:name/duplicate", requireAuth, asyncRoute(async (req, res) => {
  const world = await trackedOperation(req, "world.duplicate", "duplicating-world", (manager) => manager.duplicateWorld(req.params.name, req.body.name));
  res.json({ ok: true, world });
}));

app.post("/api/servers/:id/worlds/:name/activate", requireAuth, asyncRoute(async (req, res) => {
  const world = await trackedOperation(req, "world.activate", "activating-world", (manager) => manager.activateWorld(req.params.name));
  res.json({ ok: true, world });
}));

app.delete("/api/servers/:id/worlds/:name", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, req.params.name);
  await trackedOperation(req, "world.reset", "resetting-world", (manager) => manager.resetWorld(req.params.name));
  res.json({ ok: true });
}));

app.post("/api/servers/:id/worlds/:name/restore", requireAuth, asyncRoute(async (req, res) => {
  requireConfirmation(req, "RESTORE");
  await trackedOperation(req, "world.restore", "restoring-world", (manager) => manager.restoreWorldFromBackup(req.body.backup, req.params.name));
  res.json({ ok: true });
}));

app.post("/api/servers/:id/files/upload", requireAuth, upload.single("file"), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier manquant." });
  try {
    const relativePath = [String(req.body.path || ""), path.basename(req.file.originalname)].filter(Boolean).join("/");
    const file = await serverFrom(req).uploadFile(relativePath, req.file.path, req.body.overwrite === "true");
    await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: "file.upload", message: file.path });
    res.status(201).json({ ok: true, file });
  } finally {
    await fsp.rm(req.file.path, { force: true }).catch(() => {});
  }
}));

app.get("/api/servers/:id/file/download", requireAuth, asyncRoute(async (req, res) => {
  const file = await serverFrom(req).resolveDownload(String(req.query.path || ""));
  res.download(file);
}));

app.patch("/api/servers/:id/file", requireAuth, asyncRoute(async (req, res) => {
  const file = await serverFrom(req).renameFile(req.body.path, req.body.name);
  await activity.add({ serverId: req.params.id, user: req.session?.user?.username || "admin", action: "file.rename", message: file.path });
  res.json({ ok: true, file });
}));

app.get("/api/activity", requireAuth, (req, res) => {
  res.json({ entries: activity.list(String(req.query.serverId || ""), req.query.limit) });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user || { username: "admin", role: "admin", totpEnabled: false } });
});

app.get("/api/users", requireAuth, (req, res) => {
  res.json({ users: users.list() });
});

app.post("/api/users", requireAuth, asyncRoute(async (req, res) => {
  const user = await users.create(req.body);
  await activity.add({ user: req.session.user?.username || "admin", action: "user.create", message: user.username });
  res.status(201).json({ ok: true, user });
}));

app.delete("/api/users/:username", requireAuth, asyncRoute(async (req, res) => {
  await users.remove(req.params.username, req.session.user?.username || "admin");
  await activity.add({ user: req.session.user?.username || "admin", action: "user.delete", message: req.params.username });
  res.json({ ok: true });
}));

app.post("/api/users/:username/totp/setup", requireAuth, asyncRoute(async (req, res) => {
  res.json(await users.beginTotp(req.params.username));
}));

app.post("/api/users/:username/totp/enable", requireAuth, asyncRoute(async (req, res) => {
  await users.enableTotp(req.params.username, req.body.token);
  res.json({ ok: true });
}));

app.delete("/api/users/:username/totp", requireAuth, asyncRoute(async (req, res) => {
  await users.disableTotp(req.params.username);
  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Erreur serveur" });
});

if (usingGeneratedPassword) {
  console.log(`ADMIN_PASSWORD automatique: ${adminPassword}`);
  console.log("Ce mot de passe est conserve dans le volume. Definis ADMIN_PASSWORD pour le remplacer.");
}

const httpServer = app.listen(port, () => {
  console.log(`Interface Bedrock prete sur le port ${port}`);
});

await fleet.startAutoServers();

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Arret propre demande par Railway (${signal}).`);
  httpServer.close();
  playit.stop();
  const forcedExit = setTimeout(() => process.exit(1), 20000);
  forcedExit.unref?.();
  await fleet.shutdown();
  clearTimeout(forcedExit);
  process.exit(0);
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));

function loginHtml(error = "") {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connexion - ServerAura</title>
  <style>
    :root { color-scheme: dark; --ink:#f7f8ff; --line:#394059; --panel:#272c42; --blue:#5b8cff; --red:#ff8d91; --bg:#111522; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; background:radial-gradient(circle at 80% 0%, rgba(91,140,255,.2), transparent 32%), var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    main { width:min(430px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:30px; box-shadow:0 18px 50px rgba(0,0,0,.28); }
    form { display:grid; gap:10px; }
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
    <h1>ServerAura</h1>
    <form method="post" action="/login">
      <label for="username">Utilisateur</label>
      <input id="username" name="username" value="admin" autocomplete="username" required>
      <label for="password">Mot de passe</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <label for="token">Code 2FA <span style="text-transform:none;font-weight:600">(si activé)</span></label>
      <input id="token" name="token" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code">
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
  <title>ServerAura</title>
  <script src="/assets/lucide.min.js"></script>
  <style>
    :root { --ink:#f4f6fa; --muted:#aeb5c2; --bg:#111318; --panel:#272a32; --panel-2:#30343d; --panel-3:#1b1e25; --line:#3c414c; --blue:#5b8cff; --blue-2:#253650; --red:#ef666c; --green:#50c982; --amber:#e8b45e; --code:#101216; --soft:#20242c; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:#151820; color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; letter-spacing:0; }
    body::before { content:""; position:fixed; inset:0; pointer-events:none; background-image:linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px); background-size:32px 32px; }
    h1 { margin:0; font-size:32px; font-weight:900; }
    h2 { margin:0; font-size:18px; font-weight:900; }
    h3 { margin:0 0 10px; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
    .shell { position:relative; z-index:1; min-height:100vh; display:grid; grid-template-columns:296px minmax(0, 1fr); }
    .sidebar { position:sticky; top:0; min-height:100vh; max-height:100vh; overflow:auto; padding:18px 18px 22px; background:#1b1e26; border-right:1px solid rgba(255,255,255,.07); display:grid; align-content:start; gap:22px; }
    .brand { display:flex; align-items:center; gap:12px; min-height:44px; font-size:25px; font-weight:950; letter-spacing:.02em; }
    .brand-mark { width:34px; height:34px; border-radius:8px; display:grid; place-items:center; background:linear-gradient(135deg, #1db7ff, #6c7bff); color:#fff; box-shadow:0 12px 24px rgba(29,183,255,.22); }
    .side-group { display:grid; gap:8px; }
    .side-group.compact .content { padding:14px; }
    .nav-item { min-height:42px; display:flex; align-items:center; gap:12px; color:var(--muted); padding:0 10px; border-radius:7px; font-weight:700; }
    .nav-item.active { color:#76a6ff; background:#22304f; }
    button.nav-item { width:100%; min-height:42px; justify-content:flex-start; border:0; background:transparent; }
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
    .tab-list select { width:auto; min-width:116px; height:40px; background:#343944; border-color:#444a56; font-weight:800; }
    .panel, section { min-width:0; background:#272b34; border:1px solid var(--line); border-radius:8px; overflow:hidden; box-shadow:0 14px 34px rgba(0,0,0,.14); }
    .head { min-height:62px; padding:16px 18px; border-bottom:1px solid rgba(255,255,255,.06); display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .content { padding:18px; }
    .actions { display:flex; flex-wrap:wrap; gap:8px; }
    button, a.button { min-height:42px; border:1px solid transparent; border-radius:7px; background:#393e49; color:var(--ink); padding:0 14px; display:inline-flex; align-items:center; justify-content:center; gap:8px; font:800 14px inherit; cursor:pointer; text-decoration:none; transition:background .15s ease, transform .15s ease, border-color .15s ease; }
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
    .metric { border:1px solid #3d434f; border-radius:8px; padding:14px; min-height:86px; background:#22262e; }
    .metric span { display:block; color:var(--muted); font-size:12px; font-weight:900; text-transform:uppercase; }
    .metric strong { display:block; margin-top:8px; font-size:17px; font-weight:800; overflow-wrap:anywhere; }
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
    .hidden { display:none !important; }
    .progress { height:8px; overflow:hidden; border-radius:4px; background:#171b25; }
    .progress > span { display:block; height:100%; width:0; background:var(--blue); transition:width .2s ease; }
    .install-panel { display:grid; gap:12px; padding:14px; border:1px solid #464c58; border-radius:8px; background:#20242c; }
    .install-panel.ready { border-color:#397e57; }
    .install-panel.error { border-color:#7a3b43; }
    .toolbar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .toolbar input[type="search"] { flex:1 1 220px; }
    .data-list { display:grid; gap:8px; }
    .data-row { min-height:54px; display:flex; align-items:center; justify-content:space-between; gap:12px; padding:10px 12px; border:1px solid #3a4260; border-radius:8px; background:#242b42; }
    .data-row-main { min-width:0; display:grid; gap:4px; }
    .data-row-main strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .badge { display:inline-flex; align-items:center; width:max-content; padding:4px 7px; border-radius:5px; background:#343c58; color:#cbd3eb; font-size:11px; font-weight:900; text-transform:uppercase; }
    .badge.ok { background:#203d31; color:#9ff0bd; }
    .badge.error { background:#442a35; color:#ffb4b7; }
    .two-columns { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:18px; align-items:start; }
    .stack { display:grid; gap:12px; }
    .console-tools { display:flex; gap:8px; padding:12px 16px; background:#181d29; border-bottom:1px solid #343b50; }
    .console-tools input { flex:1; }
    .activity-list { display:grid; gap:0; }
    .activity-row { display:grid; grid-template-columns:160px 180px 100px minmax(0, 1fr); gap:12px; padding:11px 0; border-bottom:1px solid rgba(255,255,255,.06); align-items:center; }
    .lifecycle { display:flex; align-items:center; gap:8px; flex-wrap:wrap; color:var(--muted); }
    .lifecycle span { min-height:30px; display:inline-flex; align-items:center; padding:0 9px; border:1px solid #444a55; border-radius:6px; font-size:12px; font-weight:800; }
    .lifecycle span.active { color:#15181e; border-color:var(--amber); background:var(--amber); }
    .lifecycle span.done { color:#a6edbf; border-color:#397e57; background:#203d31; }
    .lifecycle svg { width:14px; height:14px; }
    .preflight { border-color:#735d35; background:#2d281f; }
    @media (max-width: 1120px) { .shell { grid-template-columns:1fr; } .sidebar { position:relative; min-height:auto; max-height:none; } .dashboard, .tab-panel.split.active, .overview-board, .file-layout { grid-template-columns:1fr; } .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 620px) { .sidebar { min-height:auto; max-height:none; padding:12px 14px; display:flex; align-items:center; gap:12px; } .brand { font-size:19px; } .brand-mark { width:32px; height:32px; } .sidebar .plan-card, .side-group h3 { display:none; } .side-group { margin-left:auto; display:flex; } .nav-item { min-height:38px; padding:0 9px; } .nav-item { font-size:0; } .nav-item svg { margin:0; } .main { padding:14px; } .overview-hero, .hero { display:grid; align-items:start; } .hero .actions { justify-content:flex-start; } .tabs-nav { display:grid; overflow:auto; } .tab-list { flex-wrap:nowrap; } .grid, .left-column .grid, .fields, .server-stats, .form-grid, .two-columns { grid-template-columns:1fr; } .server-card { grid-template-columns:42px minmax(0, 1fr); } .server-card-actions { grid-column:1 / -1; justify-content:flex-start; } .actions button, .actions a.button { flex:1 1 auto; } .modal-footer { display:grid; grid-template-columns:1fr 1fr; } .activity-row { grid-template-columns:1fr; gap:4px; } .lifecycle i { display:none; } }
    @media (max-width: 620px) { .shell { grid-template-rows:68px auto; align-content:start; } .sidebar { height:68px; min-height:68px; max-height:68px; } .server-card-meta { display:grid; gap:4px; } }
    /* Professional control-panel theme */
    :root { --ink:#f2f4f7; --muted:#8d96a5; --bg:#0d1015; --panel:#171b22; --panel-2:#1d222b; --panel-3:#12161c; --line:#2a303a; --blue:#3b82f6; --blue-2:#182a46; --red:#e0525b; --green:#38b875; --amber:#d7a449; --code:#090c10; --soft:#14181f; }
    body { background:var(--bg); color:var(--ink); font-family:Inter, "Segoe UI", system-ui, sans-serif; font-size:14px; }
    body::before { display:none; }
    h1 { font-size:26px; line-height:1.2; font-weight:750; }
    h2 { font-size:16px; font-weight:700; }
    h3 { font-size:11px; font-weight:650; letter-spacing:0; }
    .shell { grid-template-columns:248px minmax(0, 1fr); }
    .sidebar { padding:20px 14px; background:#11151b; border-color:#242a33; gap:26px; }
    .brand { padding:0 8px; font-size:18px; font-weight:750; }
    .brand-mark { width:32px; height:32px; border-radius:6px; background:#2563eb; box-shadow:none; }
    .nav-item { min-height:40px; border-radius:6px; font-size:13px; font-weight:600; }
    .nav-item.active { color:#eaf2ff; background:#1d2d48; box-shadow:inset 2px 0 0 #60a5fa; }
    .plan-card { margin-top:auto; padding:12px; border-color:#2c333e; background:#151a21; box-shadow:none; }
    .plan-title { font-weight:650; }
    .plan-card .server-icon { width:30px; height:30px; background:#173b2a; color:#68d998; }
    .main { padding:24px clamp(20px, 3vw, 44px) 44px; gap:20px; }
    .view.active { gap:20px; }
    .overview-hero { min-height:74px; align-items:center; padding:0; }
    .overview-hero p { margin-top:5px; font-size:13px; font-weight:450; }
    .topbar { display:contents; }
    #detailView.active { display:grid; grid-template-columns:216px minmax(0, 1fr); gap:20px; align-items:start; }
    #detailView .crumb, #detailView .hero { grid-column:1 / -1; }
    #detailView .crumb { grid-row:1; width:max-content; font-size:13px; font-weight:550; }
    #detailView .hero { grid-row:2; align-items:center; min-height:68px; padding-bottom:18px; border-bottom:1px solid var(--line); }
    .hero-meta { margin-top:7px; gap:14px; font-size:12px; font-weight:500; }
    .hero .actions { align-items:center; }
    .tabs-nav { grid-column:1; grid-row:3; position:sticky; top:20px; min-height:0; padding:8px; display:grid; gap:8px; background:transparent; border:0; border-radius:0; }
    .tab-list { display:grid; gap:3px; }
    #moreTab { display:none !important; }
    .tab { width:100%; min-height:38px; padding:0 10px; justify-content:flex-start; gap:10px; border-radius:6px; font-size:13px; font-weight:550; }
    .tab:hover { background:#181e27; }
    .tab.active { color:#eff6ff; background:#1b2d49; box-shadow:inset 2px 0 0 #60a5fa; }
    .tabs-nav > .actions { padding-top:8px; border-top:1px solid var(--line); }
    #refreshDetail { width:100%; background:transparent; }
    #detailView > .tab-panel.active { grid-column:2; grid-row:3; min-width:0; }
    section, .panel { background:var(--panel); border-color:var(--line); border-radius:7px; box-shadow:none; }
    .head { min-height:56px; padding:14px 18px; border-color:#252b34; }
    .content { padding:18px; }
    button, a.button { min-height:38px; border-radius:6px; padding:0 12px; background:#232933; border-color:#303744; font-size:13px; font-weight:600; box-shadow:none; }
    button:hover, a.button:hover { background:#2b3340; border-color:#3a4453; }
    button.primary, button.blue { background:#2563eb; border-color:#2563eb; }
    button.primary:hover, button.blue:hover { background:#3472f0; }
    button.red { background:transparent; border-color:#65353b; color:#ff9ba1; }
    button.red:hover { background:#522b31; color:#fff; }
    button.amber { background:#29261e; border-color:#55472e; color:#e8c47d; }
    button.icon { width:38px; }
    label { margin-bottom:6px; color:#9aa3b2; font-size:11px; font-weight:650; letter-spacing:0; }
    input, select { height:40px; padding:0 11px; background:#11161e; border-color:#303844; border-radius:6px; }
    input:focus, select:focus, textarea:focus { outline:2px solid rgba(59,130,246,.18); border-color:#4c8bf5; }
    textarea { background:#0e131a; border-color:#303844; border-radius:6px; }
    .grid, .left-column .grid { grid-template-columns:repeat(3, minmax(150px, 1fr)); gap:0; border:1px solid var(--line); border-radius:7px; overflow:hidden; }
    .metric { min-height:92px; padding:15px 16px; border:0; border-right:1px solid var(--line); border-bottom:1px solid var(--line); border-radius:0; background:transparent; }
    .metric:nth-child(3n) { border-right:0; }
    .metric span { font-size:10px; font-weight:650; }
    .metric strong { margin-top:10px; font-size:16px; font-weight:650; }
    .install-panel { padding:16px; background:#131820; border-color:#2d3540; }
    .install-panel.ready { border-color:#28583f; }
    .preflight { background:#1b1914; border-color:#4c4029; }
    .lifecycle span { border-color:#343c47; background:#171c23; font-weight:550; }
    .server-card { min-height:78px; padding:13px 14px; background:transparent; border-color:var(--line); }
    .server-card:hover { background:#1b2028; border-color:#38414e; }
    .server-card.active { border-color:#3b82f6; box-shadow:inset 2px 0 0 #3b82f6; }
    .server-icon { background:#173b2a; color:#68d998; box-shadow:none; }
    .server-card-title strong { font-size:15px; font-weight:650; }
    .server-card-meta { font-weight:450; }
    .pill { border-radius:5px; padding:5px 8px; background:#1b212a; border-color:#343d49; font-size:12px; font-weight:600; }
    .pill.ok { background:#142b21; border-color:#28583f; }
    .pill.off { background:#2b1b1e; border-color:#63353b; }
    .badge { background:#222a36; color:#b8c1cf; font-weight:650; }
    .badge.ok { background:#153025; color:#84dba7; }
    .data-row, .backup-list li, .file-item { background:#141920; border-color:#29313b; }
    .toast { background:#1d2531; border-color:#3a4657; border-radius:6px; }
    .danger-zone { margin-top:24px; padding-top:18px; border-top:1px solid #3b292d; display:flex; align-items:center; justify-content:space-between; gap:18px; }
    .danger-zone > div { display:grid; gap:4px; }
    .danger-zone strong { color:#f2c6c9; font-size:13px; }
    .danger-zone span { color:var(--muted); font-size:12px; }
    .progress { height:5px; background:#0b0f14; }
    pre { background:#090d12; }
    dialog.modal { background:#171c24; border-color:#333b47; }
    .modal-footer { background:#13171e; }
    @media (max-width: 1100px) {
      .shell { grid-template-columns:220px minmax(0, 1fr); }
      .grid, .left-column .grid { grid-template-columns:repeat(2, minmax(140px, 1fr)); }
      .metric:nth-child(3n) { border-right:1px solid var(--line); }
      .metric:nth-child(2n) { border-right:0; }
    }
    @media (max-width: 820px) {
      .shell { grid-template-columns:1fr; grid-template-rows:64px auto; }
      .sidebar { position:relative; min-height:64px; max-height:64px; padding:10px 14px; display:flex; align-items:center; gap:12px; overflow:hidden; }
      .sidebar .plan-card, .side-group h3 { display:none; }
      .side-group { margin-left:auto; display:flex; }
      .nav-item { font-size:0; width:40px; padding:0; justify-content:center; }
      .main { padding:16px; }
      #detailView.active { grid-template-columns:1fr; gap:14px; }
      #detailView .crumb, #detailView .hero, #detailView .tabs-nav, #detailView > .tab-panel.active { grid-column:1; grid-row:auto; }
      .tabs-nav { position:relative; top:auto; display:flex; overflow-x:auto; padding:5px; background:#141920; border:1px solid var(--line); border-radius:7px; }
      .tab-list { display:flex; flex-wrap:nowrap; gap:3px; }
      .tab { width:auto; min-width:max-content; padding:0 11px; }
      .tabs-nav > .actions { padding:0 0 0 5px; border:0; border-left:1px solid var(--line); }
      #refreshDetail { width:38px; }
      .hero { display:grid; }
      .hero .actions { justify-content:flex-start; }
    }
    @media (max-width: 560px) {
      h1 { font-size:22px; }
      .overview-hero { display:grid; }
      .grid, .left-column .grid, .fields, .form-grid, .two-columns { grid-template-columns:1fr; }
      .metric, .metric:nth-child(2n), .metric:nth-child(3n) { border-right:0; }
      .danger-zone { align-items:stretch; flex-direction:column; }
      .danger-zone button { width:100%; }
      .hero .actions button { flex:1 1 auto; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark"><i data-lucide="zap"></i></span><span>ServerAura</span></div>
      <div class="side-group">
        <h3>Menu</h3>
        <button class="nav-item active" id="navServers"><i data-lucide="cloud"></i>Mes serveurs</button>
        <button class="nav-item" id="navAccounts"><i data-lucide="users"></i>Comptes</button>
      </div>
      <div class="plan-card">
        <div class="plan-title"><span class="server-icon"><i data-lucide="server"></i></span><span>État global</span></div>
        <span class="muted" id="sidebarSummary">Chargement…</span>
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
            <button class="tab active" data-tab="overview"><i data-lucide="layout-dashboard"></i>Aperçu</button>
            <button class="tab" data-tab="console" data-requires-first-run><i data-lucide="terminal"></i>Console</button>
            <button class="tab" data-tab="config" data-requires-first-run><i data-lucide="sliders-horizontal"></i>Configuration</button>
            <button class="tab" data-tab="performance"><i data-lucide="gauge"></i>Performances</button>
            <button class="tab" data-tab="players" data-requires-first-run><i data-lucide="users"></i>Joueurs</button>
            <button class="tab" data-tab="worlds" data-requires-first-run><i data-lucide="map"></i>Mondes</button>
            <button class="tab" data-tab="files" data-requires-first-run><i data-lucide="folder"></i>Fichiers</button>
            <button class="tab" data-tab="backups" data-requires-first-run><i data-lucide="archive"></i>Sauvegardes</button>
            <button class="tab" data-tab="activity"><i data-lucide="history"></i>Activité</button>
            <select class="hidden" id="moreTab" data-requires-first-run aria-label="Plus de sections"><option value="">Plus…</option><option value="files">Fichiers</option><option value="backups">Sauvegardes</option></select>
          </div>
          <div class="actions">
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
              </div>
            </div>
            <div class="content">
              <div class="grid">
                <div class="metric" data-requires-installed><span>Version</span><strong id="serverVersion">...</strong></div>
                <div class="metric" data-requires-first-run><span>Uptime</span><strong id="serverUptime">...</strong></div>
                <div class="metric" data-requires-first-run><span>Joueurs</span><strong id="playerCount">...</strong></div>
                <div class="metric" data-requires-first-run><span>Stockage utilisé</span><strong id="diskUsage">...</strong></div>
                <div class="metric"><span>Ressources</span><strong id="resourceAllocation">...</strong></div>
                <div class="metric" data-requires-first-run><span>Dernière sauvegarde</span><strong id="lastBackup">...</strong></div>
                <div class="metric" data-requires-first-run><span>Adresse locale</span><strong id="serverAddress">...</strong><button class="icon" id="copyAddress" title="Copier l’adresse"><i data-lucide="copy"></i></button></div>
                <div class="metric" data-requires-first-run><span>Adresse publique</span><strong id="publicAddress">...</strong></div>
                <div class="metric" data-requires-first-run><span>État réseau UDP</span><strong id="networkState">...</strong></div>
                <div class="metric hidden" id="lastErrorMetric"><span>Dernière erreur</span><strong id="lastServerError">...</strong></div>
              </div>
              <div class="install-panel" id="installPanel" style="margin-top:16px">
                <div class="lifecycle" id="lifecycleSteps"><span data-lifecycle="created">Créé</span><i data-lucide="chevron-right"></i><span data-lifecycle="installed">Installé</span><i data-lucide="chevron-right"></i><span data-lifecycle="initializing">Initialisation</span><i data-lucide="chevron-right"></i><span data-lifecycle="operational">Opérationnel</span></div>
                <div class="row"><div><strong id="installTitle">État de l’installation</strong><div class="muted" id="installMessage"></div></div><span class="badge" id="installBadge">...</span></div>
                <div class="progress"><span id="operationProgress"></span></div>
                <div class="actions">
                  <button class="blue" id="installServer"><i data-lucide="download"></i>Installer</button>
                  <button id="checkVersion"><i data-lucide="search"></i>Vérifier la version</button>
                  <button class="amber" id="updateServer"><i data-lucide="refresh-cw"></i>Mettre à jour</button>
                  <button id="chooseBinary" type="button"><i data-lucide="upload"></i>Importer le binaire</button>
                  <input class="hidden" id="binaryUpload" type="file">
                </div>
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
              <label class="checkrow" data-requires-first-run><input id="serverAutoStart" type="checkbox"> Démarrage automatique</label>
              <div class="danger-zone">
                <div><strong>Supprimer ce serveur</strong><span>Les fichiers, mondes et sauvegardes de cette instance seront supprimés.</span></div>
                <button class="red" id="deleteServer"><i data-lucide="trash-2"></i>Supprimer</button>
              </div>
            </div>
          </section>

        </div>
      </div>

      <div class="tab-panel" data-panel="performance">
        <section>
          <div class="head">
            <h2>Performances</h2>
            <button class="primary" id="savePerformance"><i data-lucide="save"></i>Enregistrer</button>
          </div>
          <div class="content">
            <div class="row" style="margin-bottom:16px"><strong>Ressources du serveur</strong><span class="badge" id="performanceBadge">Équilibré</span></div>
            <div class="form-grid">
              <div><label for="performanceProfile">Profil</label><select id="performanceProfile"><option value="economy">Économie</option><option value="balanced">Équilibré</option><option value="performance">Performance</option><option value="custom">Personnalisé</option></select></div>
              <div><label for="resourceRam">RAM allouée (Mo)</label><input id="resourceRam" type="number" min="256" max="131072" step="256" title="Budget RAM du serveur Bedrock"></div>
              <div><label for="resourceCpu">Cœurs CPU</label><input id="resourceCpu" type="number" min="0.25" max="64" step="0.25"></div>
              <div><label for="resourceStorage">Stockage maximal (Go)</label><input id="resourceStorage" type="number" min="1" max="4096"></div>
              <div><label for="resourceViewDistance">Distance d’affichage</label><input id="resourceViewDistance" type="number" min="5" max="96"></div>
              <div><label for="resourceTickDistance">Distance de simulation</label><input id="resourceTickDistance" type="number" min="4" max="12"></div>
            </div>
          </div>
        </section>
      </div>

      <div class="tab-panel" data-panel="console">
          <section>
            <div class="head">
              <h2>Console</h2>
              <button class="icon" id="refreshLogs" title="Actualiser"><i data-lucide="refresh-cw"></i></button>
            </div>
            <div class="console-tools">
              <input id="logSearch" type="search" placeholder="Rechercher dans les logs">
              <select id="logFilter" aria-label="Filtrer les logs"><option value="all">Tout</option><option value="errors">Erreurs</option><option value="commands">Commandes</option></select>
            </div>
            <pre id="logs"></pre>
            <div class="content">
              <div class="actions">
                <input class="command" id="commandInput" list="commandHistory" placeholder="Entrer une commande...">
                <datalist id="commandHistory"></datalist>
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
                <div><label for="propGamemode">Mode de jeu</label><select id="propGamemode"><option value="survival">Survie</option><option value="creative">Créatif</option><option value="adventure">Aventure</option></select></div>
                <div><label for="propDifficulty">Difficulté</label><select id="propDifficulty"><option value="peaceful">Paisible</option><option value="easy">Facile</option><option value="normal">Normale</option><option value="hard">Difficile</option></select></div>
                <div><label for="propMaxPlayers">Joueurs maximum</label><input id="propMaxPlayers" type="number" min="1"></div>
                <div><label for="propAllowCheats">Commandes de triche</label><select id="propAllowCheats"><option value="false">Désactivées</option><option value="true">Activées</option></select></div>
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
            <div class="install-panel" style="margin-bottom:16px">
              <div class="row"><strong>Sauvegardes automatiques</strong><button id="saveBackupPolicy"><i data-lucide="save"></i>Enregistrer</button></div>
              <div class="form-grid">
                <div><label for="backupEnabled">Planification</label><select id="backupEnabled"><option value="false">Désactivée</option><option value="true">Activée</option></select></div>
                <div><label for="backupInterval">Fréquence</label><select id="backupInterval"><option value="60">Chaque heure</option><option value="360">Toutes les 6 heures</option><option value="720">Toutes les 12 heures</option><option value="1440">Chaque jour</option><option value="10080">Chaque semaine</option></select></div>
                <div><label for="backupRetention">Nombre conservé</label><input id="backupRetention" type="number" min="1" max="100" value="10"></div>
              </div>
            </div>
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
              <button id="chooseFileUpload"><i data-lucide="upload"></i>Importer</button>
              <input class="hidden" id="fileUpload" type="file">
              <div class="toolbar" id="fileBreadcrumbs"></div>
            </div>
            <div class="toolbar" style="margin-bottom:12px">
              <input id="fileSearch" type="search" placeholder="Rechercher dans ce dossier">
              <button id="renameFile"><i data-lucide="pencil"></i>Renommer</button>
              <button id="downloadFile"><i data-lucide="download"></i>Télécharger</button>
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

      <div class="tab-panel" data-panel="players">
        <div class="two-columns">
          <section>
            <div class="head"><h2>Joueurs connectés</h2><button class="icon" id="refreshPlayers" title="Actualiser"><i data-lucide="refresh-cw"></i></button></div>
            <div class="content"><div class="data-list" id="playerList"></div></div>
          </section>
          <div class="stack">
            <section>
              <div class="head"><h2>Liste blanche</h2></div>
              <div class="content stack">
                <div class="toolbar"><input id="allowlistName" placeholder="Pseudo du joueur"><button id="addAllowlist"><i data-lucide="plus"></i>Ajouter</button></div>
                <div class="data-list" id="allowlistList"></div>
              </div>
            </section>
            <section>
              <div class="head"><h2>Permissions</h2></div>
              <div class="content stack">
                <div class="toolbar"><input id="permissionXuid" placeholder="XUID"><select id="permissionRole"><option value="visitor">Visiteur</option><option value="member">Membre</option><option value="operator">Opérateur</option></select><button id="addPermission"><i data-lucide="plus"></i>Ajouter</button></div>
                <div class="data-list" id="permissionList"></div>
              </div>
            </section>
          </div>
        </div>
      </div>

      <div class="tab-panel" data-panel="worlds">
        <section>
          <div class="head"><h2>Mondes</h2><div class="actions"><button id="chooseWorldImport"><i data-lucide="upload"></i>Importer .mcworld</button><input class="hidden" id="worldImport" type="file" accept=".mcworld"></div></div>
          <div class="content"><div class="data-list" id="worldList"></div></div>
        </section>
      </div>

      <div class="tab-panel" data-panel="activity">
        <section>
          <div class="head"><h2>Historique d’activité</h2><button class="icon" id="refreshActivity" title="Actualiser"><i data-lucide="refresh-cw"></i></button></div>
          <div class="content"><div class="activity-list" id="activityList"></div></div>
        </section>
      </div>

      </div>

      <div class="view" id="accountsView">
        <div class="overview-hero"><div><h1>Comptes</h1><p>Accès au panel et sécurité.</p></div></div>
        <section>
          <div class="head"><h2>Utilisateurs</h2></div>
          <div class="content two-columns">
            <div class="stack"><div class="data-list" id="userList"></div></div>
            <div class="install-panel">
              <strong>Nouveau compte</strong>
              <div><label for="newUsername">Utilisateur</label><input id="newUsername"></div>
              <div><label for="newUserPassword">Mot de passe</label><input id="newUserPassword" type="password"></div>
              <div><label for="newUserRole">Rôle</label><select id="newUserRole"><option value="viewer">Lecture seule</option><option value="admin">Administrateur</option></select></div>
              <button class="primary" id="createUser"><i data-lucide="user-plus"></i>Créer le compte</button>
            </div>
          </div>
        </section>
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
let loadedPropertiesFor = "";
let currentFilePath = "";
let selectedFilePath = "";
let currentFiles = [];
let rawLogs = [];
let eventSource = null;
let playerState = { players: [], allowlist: [], permissions: [] };
let currentUser = { username: "admin", role: "admin" };

async function api(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const isFormData = options.body instanceof FormData;
  const headers = { ...(isFormData ? {} : { "Content-Type": "application/json" }), ...(options.headers || {}) };
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

async function loadCurrentUser() {
  const data = await api("/api/me");
  currentUser = data.user;
  $("navAccounts").classList.toggle("hidden", currentUser.role !== "admin");
  applyRole();
}

function applyRole() {
  if (currentUser.role !== "viewer") return;
  const allowed = new Set(["navServers", "navAccounts", "refreshServers", "refreshDetail", "backOverview", "refreshLogs", "refreshPlayers", "refreshActivity", "copyAddress", "checkVersion", "goUpFile", "downloadFile"]);
  document.querySelectorAll("button").forEach((button) => {
    if (button.dataset.tab !== undefined || button.dataset.server !== undefined || button.dataset.breadcrumb !== undefined || allowed.has(button.id) || button.closest('form[action="/logout"]')) return;
    button.disabled = true;
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
  $("sidebarSummary").textContent = running + " en ligne · " + servers.length + " serveur(s)";
}

function renderServerGallery() {
  const target = $("serverGallery");
  if (!target) return;
  target.innerHTML = servers.map((server) => {
    const status = server.status || {};
    const active = server.id === activeId ? " active" : "";
    const lifecycleLabels = { created:"À installer", installed:"Premier lancement", initializing:"Initialisation", error:"Erreur" };
    const pill = status.running ? '<span class="pill ok">En ligne</span>' : '<span class="pill off">' + (lifecycleLabels[status.lifecycle] || "Arrêté") + '</span>';
    const port = escapeHtmlClient(status.gamePort || "-");
    const world = status.lifecycle === "operational" ? escapeHtmlClient(status.worldName || "-") : "Configuration initiale";
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
  $("accountsView").classList.toggle("active", viewMode === "accounts");
  $("navServers").classList.toggle("active", viewMode !== "accounts");
  $("navAccounts").classList.toggle("active", viewMode === "accounts");
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
  $("moreTab").value = ["files", "backups"].includes(detailTab) ? detailTab : "";
}

function setDetailTab(tab) {
  detailTab = tab;
  renderTabs();
  if (tab === "console") refreshLogs().catch((error) => toast(error.message));
  if (tab === "backups") refreshBackups().catch((error) => toast(error.message));
  if (tab === "config") loadProperties().catch((error) => toast(error.message));
  if (tab === "files") loadFiles(currentFilePath).catch((error) => toast(error.message));
  if (tab === "players") loadPlayers().catch((error) => toast(error.message, "error"));
  if (tab === "worlds") loadWorlds().catch((error) => toast(error.message, "error"));
  if (tab === "activity") loadActivity().catch((error) => toast(error.message, "error"));
  if (tab === "accounts") loadUsers().catch((error) => toast(error.message, "error"));
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
  connectEvents();
  refreshActive().catch((error) => toast(error.message));
}

function showOverview() {
  disconnectEvents();
  viewMode = "overview";
  renderView();
  refreshServers().catch((error) => toast(error.message));
}

function showAccounts() {
  disconnectEvents();
  viewMode = "accounts";
  renderView();
  loadUsers().catch((error) => toast(error.message, "error"));
}

function connectEvents() {
  disconnectEvents();
  if (!activeId) return;
  eventSource = new EventSource(endpoint("/events"));
  eventSource.addEventListener("ready", (event) => {
    const data = JSON.parse(event.data);
    rawLogs = data.logs || [];
    renderLogs();
    updateOperation(data.operation || { type:"idle", progress:0 });
  });
  eventSource.addEventListener("logs", (event) => {
    const data = JSON.parse(event.data);
    rawLogs.push(...(data.lines || []));
    if (rawLogs.length > 1200) rawLogs.splice(0, rawLogs.length - 1200);
    renderLogs();
  });
  eventSource.addEventListener("operation", (event) => {
    const data = JSON.parse(event.data);
    updateOperation(data.operation || { type:"idle", progress:0 });
    if (data.operation?.type === "idle") refreshActive().catch(() => {});
  });
  eventSource.addEventListener("operation-error", (event) => {
    if (event.data) toast(JSON.parse(event.data).message || "Erreur serveur", "error");
  });
  eventSource.onerror = () => setConnectionState(false);
  eventSource.onopen = () => setConnectionState(true);
}

function disconnectEvents() {
  eventSource?.close();
  eventSource = null;
}

function updateOperation(operation) {
  const server = activeServer();
  if (server) {
    server.status = { ...(server.status || {}), operation };
    if (!server.status.firstStartedAt && operation.type === "starting") server.status.lifecycle = "initializing";
    renderLifecycle(server.status);
    renderInstallation(server.status);
  }
  const progress = Number(operation.progress || 0);
  $("operationProgress").style.width = progress + "%";
  renderOperationControls(operation);
}

function renderLogs() {
  const search = $("logSearch").value.trim().toLowerCase();
  const filter = $("logFilter").value;
  const lines = rawLogs.filter((line) => {
    const value = String(line);
    if (search && !value.toLowerCase().includes(search)) return false;
    if (filter === "errors" && !/error|exception|fail|warn/i.test(value)) return false;
    if (filter === "commands" && !/^\[commande\]/i.test(value)) return false;
    return true;
  });
  $("logs").textContent = lines.join("");
  $("logs").scrollTop = $("logs").scrollHeight;
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
    setPerformanceForm({ performanceProfile:"balanced" });
    $("statePill").className = "pill off";
    $("statePill").querySelector("span").textContent = "Aucun";
    ["serverVersion", "serverUptime", "playerCount", "diskUsage", "resourceAllocation", "lastBackup", "serverAddress", "publicAddress", "networkState", "lastServerError"].forEach((id) => { $(id).textContent = "-"; });
    $("logs").textContent = "";
    clearPropertyForm();
    $("backupList").innerHTML = '<li><span class="muted">Aucun serveur sélectionné.</span></li>';
  ["startBtn", "restartBtn", "stopBtn", "saveServer", "savePerformance", "deleteServer", "sendCommand", "createBackup", "saveProperties", "saveFile", "deleteFile", "installServer", "updateServer"].forEach((id) => {
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
  setPerformanceForm(server.resources || { performanceProfile:"balanced" });
  ["startBtn", "restartBtn", "stopBtn", "saveServer", "savePerformance", "deleteServer", "sendCommand", "createBackup", "saveProperties", "saveFile", "deleteFile", "installServer", "updateServer"].forEach((id) => {
    $(id).disabled = false;
  });
  $("startBtn").disabled = Boolean(status.running);
  ["restartBtn", "stopBtn", "sendCommand"].forEach((id) => {
    $(id).disabled = !status.running;
  });
  $("statePill").className = "pill " + (status.running ? "ok" : "off");
  $("statePill").querySelector("span").textContent = status.lifecycle === "error" ? "Erreur" : (status.running ? "En ligne" : (status.lifecycle === "created" ? "À installer" : (status.lifecycle === "installed" ? "Premier lancement" : "Arrêté")));
  $("serverVersion").textContent = status.version || "Inconnue";
  $("serverUptime").textContent = formatDuration(status.uptimeSeconds || 0);
  $("playerCount").textContent = server.playerCount ?? "-";
  $("diskUsage").textContent = status.diskUsageLabel || "-";
  $("resourceAllocation").textContent = (server.resources?.ramMb || 2048) + " Mo · " + (server.resources?.cpuCores || 2) + " cœur(s)";
  $("lastBackup").textContent = status.lastBackup ? formatDate(status.lastBackup.createdAt) : "Aucune";
  $("serverAddress").textContent = status.network?.localAddress || serverAddress(status);
  $("publicAddress").textContent = status.network?.publicAddress || (status.playit?.running ? "À configurer sur Playit.gg" : "Non configurée");
  const networkLabels = { "expected-open":"En écoute", closed:"Fermé", "in-use":"Port utilisé" };
  $("networkState").textContent = status.playit?.enabled
    ? (status.playit.running
      ? (status.network?.publicAddress ? "Tunnel Playit actif" : "Agent Playit actif")
      : (status.playit.state === "starting" ? "Connexion à Playit" : "Erreur Playit"))
    : (networkLabels[status.network?.udpState] || "Inconnu");
  $("lastServerError").textContent = status.lastError || status.error || "Aucune";
  $("lastErrorMetric").classList.toggle("hidden", !status.lastError && !status.error);
  $("backupEnabled").value = String(Boolean(server.backupPolicy?.enabled));
  $("backupInterval").value = String(server.backupPolicy?.intervalMinutes || 360);
  $("backupRetention").value = server.backupPolicy?.retention || 10;
  renderInstallation(status);
  renderLifecycle(status);
  renderOperationControls(status.operation || { type:"idle", progress:0 });
  lucide.createIcons();
  applyRole();
}

function renderLifecycle(status) {
  const lifecycle = status.lifecycle || "created";
  const firstRun = lifecycle === "operational";
  const installed = Boolean(status.installed);
  document.querySelectorAll("[data-requires-first-run]").forEach((element) => element.classList.toggle("hidden", !firstRun));
  document.querySelectorAll("[data-requires-installed]").forEach((element) => element.classList.toggle("hidden", !installed));
  if (!firstRun && ["console", "config", "players", "worlds", "files", "backups"].includes(detailTab)) {
    detailTab = "overview";
    renderTabs();
  }
  const order = ["created", "installed", "initializing", "operational"];
  const currentIndex = lifecycle === "error" ? Math.max(0, order.indexOf(installed ? "installed" : "created")) : order.indexOf(lifecycle);
  document.querySelectorAll("[data-lifecycle]").forEach((step) => {
    const index = order.indexOf(step.dataset.lifecycle);
    step.classList.toggle("done", index < currentIndex);
    step.classList.toggle("active", index === currentIndex);
  });
  $("startBtn").classList.toggle("hidden", !installed || status.running);
  $("startBtn").innerHTML = '<i data-lucide="play"></i>' + (firstRun ? "Démarrer" : "Premier démarrage");
  $("restartBtn").classList.toggle("hidden", !firstRun);
  $("stopBtn").classList.toggle("hidden", !firstRun && !status.running);
  $("installPanel").classList.toggle("preflight", !firstRun);
  $("sidebarSummary").textContent = servers.filter((item) => item.status?.running).length + " en ligne · " + servers.length + " serveur(s)";
}

function renderInstallation(status) {
  const state = status.installationState || "not-installed";
  const lifecycle = status.lifecycle || "created";
  const firstRun = lifecycle === "operational";
  const panel = $("installPanel");
  panel.className = "install-panel " + (state === "ready" ? "ready" : (state === "error" ? "error" : ""));
  const labels = { created:"Installation requise", installed:"Prêt pour le premier démarrage", initializing:"Initialisation du serveur", operational:"Serveur opérationnel", error:"Action requise" };
  $("installTitle").textContent = labels[lifecycle] || "État inconnu";
  $("installBadge").textContent = lifecycle === "operational" ? "Opérationnel" : (lifecycle === "initializing" ? "En cours" : "À terminer");
  $("installBadge").className = "badge " + (lifecycle === "operational" ? "ok" : (lifecycle === "error" ? "error" : ""));
  const network = status.network || {};
  const address = network.publicAddress || network.localAddress || "Adresse indisponible";
  const messages = {
    created:"Telecharge et installe automatiquement la version officielle de Bedrock.",
    installed:"Le binaire est présent. Effectue maintenant le premier démarrage pour initialiser les fichiers et le monde.",
    initializing:"Bedrock prépare actuellement le serveur et son premier monde.",
    operational:"Version " + (status.version || "inconnue") + " · " + address + (network.warning ? " · " + network.warning : ""),
    error:status.lastError || "Corrige l’erreur puis relance l’étape en attente."
  };
  $("installMessage").textContent = messages[lifecycle] || messages.created;
  $("installServer").disabled = Boolean(status.installed) || state === "installing";
  $("updateServer").disabled = !status.installed || state === "installing";
  $("installServer").classList.toggle("hidden", Boolean(status.installed));
  $("chooseBinary").classList.toggle("hidden", Boolean(status.installed) && lifecycle !== "error");
  $("checkVersion").classList.toggle("hidden", !firstRun);
  $("updateServer").classList.toggle("hidden", !firstRun);
}

function renderOperationControls(operation) {
  const type = operation?.type || "idle";
  const active = type !== "idle";
  const labels = {
    starting:"Démarrage en cours", stopping:"Arrêt en cours", restarting:"Redémarrage en cours",
    "backing-up":"Sauvegarde en cours", restoring:"Restauration en cours", installing:"Installation en cours",
    updating:"Mise à jour en cours", "importing-world":"Import du monde", "duplicating-world":"Duplication du monde",
    "resetting-world":"Réinitialisation du monde", "restoring-world":"Restauration du monde", "activating-world":"Activation du monde"
  };
  if (active) {
    $("statePill").className = "pill";
    $("statePill").querySelector("span").textContent = labels[type] || "Opération en cours";
  }
  $("operationProgress").style.width = (active ? Number(operation.progress || 4) : 0) + "%";
  const lifecycle = ["startBtn", "restartBtn", "stopBtn", "installServer", "updateServer"];
  if (active) lifecycle.forEach((id) => { $(id).disabled = true; });
  if (active && ["backing-up", "restoring", "updating", "installing"].includes(type)) $("createBackup").disabled = true;
}

function formatDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  if (!value) return "Arrêté";
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  return [days && days + "j", hours && hours + "h", minutes + "min"].filter(Boolean).join(" ");
}

function formatDate(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle:"short", timeStyle:"short" }).format(new Date(value));
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
  const [data, history] = await Promise.all([api(endpoint("/logs?limit=400")), api(endpoint("/commands"))]);
  rawLogs = data.logs || [];
  $("commandHistory").innerHTML = (history.commands || []).map((entry) => '<option value="' + escapeHtmlClient(entry.command) + '"></option>').join("");
  renderLogs();
}

async function refreshBackups() {
  const data = await api(endpoint("/backups"));
  $("backupList").innerHTML = data.backups.map((backup) => {
    const encoded = encodeURIComponent(backup.name);
    const origins = { manual:"Manuelle", automatic:"Automatique", update:"Avant mise à jour", legacy:"Ancienne" };
    return '<li>' +
      '<div class="row"><div><strong>' + escapeHtmlClient(backup.name) + '</strong><div class="muted">' + formatDate(backup.createdAt) + ' · ' + escapeHtmlClient(origins[backup.origin] || backup.origin) + '</div></div><span class="muted">' + escapeHtmlClient(backup.sizeLabel) + '</span></div>' +
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

const PERFORMANCE_PRESETS = {
  economy:{ ramMb:1024, cpuCores:1, storageGb:5, viewDistance:12, tickDistance:4 },
  balanced:{ ramMb:2048, cpuCores:2, storageGb:10, viewDistance:24, tickDistance:6 },
  performance:{ ramMb:4096, cpuCores:4, storageGb:20, viewDistance:32, tickDistance:8 }
};

function setPerformanceForm(resources) {
  const profile = resources.performanceProfile || "balanced";
  const values = { ...PERFORMANCE_PRESETS.balanced, ...(PERFORMANCE_PRESETS[profile] || {}), ...resources };
  $("performanceProfile").value = profile;
  $("resourceRam").value = values.ramMb;
  $("resourceCpu").value = values.cpuCores;
  $("resourceStorage").value = values.storageGb;
  $("resourceViewDistance").value = values.viewDistance;
  $("resourceTickDistance").value = values.tickDistance;
  $("performanceBadge").textContent = { economy:"Économie", balanced:"Équilibré", performance:"Performance", custom:"Personnalisé" }[profile];
}

function collectPerformanceForm() {
  return {
    performanceProfile:$("performanceProfile").value,
    ramMb:Number($("resourceRam").value), cpuCores:Number($("resourceCpu").value),
    storageGb:Number($("resourceStorage").value), viewDistance:Number($("resourceViewDistance").value),
    tickDistance:Number($("resourceTickDistance").value)
  };
}

function serverAddress(status) {
  const ip = (status.hostIps && status.hostIps[0]) || "127.0.0.1";
  return ip + ":" + (status.gamePort || "19132");
}

async function loadFiles(path = "") {
  currentFilePath = path || "";
  const data = await api(endpoint("/files?path=") + encodeURIComponent(currentFilePath));
  currentFiles = data.files || [];
  renderBreadcrumbs();
  renderFiles();
}

async function loadPlayers() {
  playerState = await api(endpoint("/players"));
  const server = activeServer();
  if (server) server.playerCount = playerState.players.length;
  $("playerCount").textContent = playerState.players.length;
  $("playerList").innerHTML = playerState.players.map((name) => '<div class="data-row"><div class="data-row-main"><strong>' + escapeHtmlClient(name) + '</strong><span class="badge ok">En ligne</span></div><button class="red" data-kick-player="' + escapeHtmlClient(name) + '"><i data-lucide="log-out"></i>Expulser</button></div>').join("") || '<div class="muted">Aucun joueur connecté.</div>';
  $("allowlistList").innerHTML = playerState.allowlist.map((entry, index) => '<div class="data-row"><strong>' + escapeHtmlClient(entry.name) + '</strong><button class="danger-icon" data-remove-allow="' + index + '" title="Retirer"><i data-lucide="trash-2"></i></button></div>').join("") || '<div class="muted">Liste vide.</div>';
  $("permissionList").innerHTML = playerState.permissions.map((entry, index) => '<div class="data-row"><div class="data-row-main"><strong>' + escapeHtmlClient(entry.xuid) + '</strong><span class="badge">' + escapeHtmlClient(entry.permission) + '</span></div><button class="danger-icon" data-remove-permission="' + index + '" title="Retirer"><i data-lucide="trash-2"></i></button></div>').join("") || '<div class="muted">Aucune permission personnalisée.</div>';
  document.querySelectorAll("[data-kick-player]").forEach((button) => { button.onclick = () => action("Joueur expulsé.", () => api(endpoint("/players/") + encodeURIComponent(button.dataset.kickPlayer) + "/kick", { method:"POST", body:"{}" })); });
  document.querySelectorAll("[data-remove-allow]").forEach((button) => { button.onclick = () => saveAllowlist(playerState.allowlist.filter((_entry, index) => index !== Number(button.dataset.removeAllow))); });
  document.querySelectorAll("[data-remove-permission]").forEach((button) => { button.onclick = () => savePermissions(playerState.permissions.filter((_entry, index) => index !== Number(button.dataset.removePermission))); });
  lucide.createIcons();
  applyRole();
}

async function saveAllowlist(entries) {
  const data = await api(endpoint("/allowlist"), { method:"PUT", body:JSON.stringify({ entries }) });
  playerState.allowlist = data.allowlist;
  await loadPlayers();
}

async function savePermissions(entries) {
  const data = await api(endpoint("/permissions"), { method:"PUT", body:JSON.stringify({ entries }) });
  playerState.permissions = data.permissions;
  await loadPlayers();
}

async function loadWorlds() {
  const data = await api(endpoint("/worlds"));
  $("worldList").innerHTML = data.worlds.map((world) => {
    const encoded = encodeURIComponent(world.name);
    return '<div class="data-row"><div class="data-row-main"><strong>' + escapeHtmlClient(world.name) + '</strong><span class="muted">' + escapeHtmlClient(world.sizeLabel) + ' · ' + formatDate(world.modifiedAt) + '</span>' + (world.active ? '<span class="badge ok">Actif</span>' : '') + '</div><div class="actions">' + (world.active ? '' : '<button data-activate-world="' + encoded + '"><i data-lucide="check"></i>Activer</button>') + '<a class="button" href="' + endpoint("/worlds/") + encoded + '/download"><i data-lucide="download"></i>Télécharger</a><button data-duplicate-world="' + encoded + '"><i data-lucide="copy"></i>Dupliquer</button><button data-restore-world="' + encoded + '"><i data-lucide="history"></i>Restaurer</button><button class="danger-icon" data-reset-world="' + encoded + '" title="Réinitialiser"><i data-lucide="trash-2"></i></button></div></div>';
  }).join("") || '<div class="muted">Aucun monde trouvé.</div>';
  document.querySelectorAll("[data-duplicate-world]").forEach((button) => { button.onclick = () => duplicateWorld(decodeURIComponent(button.dataset.duplicateWorld)); });
  document.querySelectorAll("[data-activate-world]").forEach((button) => { button.onclick = () => action("Monde activé.", () => api(endpoint("/worlds/") + button.dataset.activateWorld + "/activate", { method:"POST", body:"{}" })).then(loadWorlds); });
  document.querySelectorAll("[data-reset-world]").forEach((button) => { button.onclick = () => resetWorld(decodeURIComponent(button.dataset.resetWorld)); });
  document.querySelectorAll("[data-restore-world]").forEach((button) => { button.onclick = () => restoreWorld(decodeURIComponent(button.dataset.restoreWorld)); });
  lucide.createIcons();
  applyRole();
}

async function duplicateWorld(name) {
  const newName = await requestTextInput("Dupliquer le monde", "Nom de la copie");
  if (!newName) return;
  await action("Monde dupliqué.", () => api(endpoint("/worlds/") + encodeURIComponent(name) + "/duplicate", { method:"POST", body:JSON.stringify({ name:newName }) }));
  await loadWorlds();
}

async function resetWorld(name) {
  if (!await requireTypedConfirmation("Le monde sera supprimé et régénéré au prochain démarrage.", name, "Réinitialiser le monde")) return;
  await action("Monde réinitialisé.", () => api(endpoint("/worlds/") + encodeURIComponent(name), { method:"DELETE", body:JSON.stringify({ confirm:name }) }));
  await loadWorlds();
}

async function restoreWorld(name) {
  const data = await api(endpoint("/backups"));
  const backup = await requestTextInput("Restaurer le monde", "Nom exact de la sauvegarde ZIP");
  if (!backup || !data.backups.some((item) => item.name === backup)) return toast("Sauvegarde introuvable.", "error");
  if (!await requireTypedConfirmation("Le monde actuel sera remplacé depuis la sauvegarde.", "RESTORE", "Restaurer le monde")) return;
  await action("Monde restauré.", () => api(endpoint("/worlds/") + encodeURIComponent(name) + "/restore", { method:"POST", body:JSON.stringify({ backup, confirm:"RESTORE" }) }));
}

async function loadActivity() {
  const data = await api("/api/activity?serverId=" + encodeURIComponent(activeId));
  $("activityList").innerHTML = data.entries.map((entry) => '<div class="activity-row"><span class="muted">' + formatDate(entry.createdAt) + '</span><strong>' + escapeHtmlClient(entry.action) + '</strong><span class="badge ' + (entry.status === "error" ? "error" : "ok") + '">' + escapeHtmlClient(entry.status) + '</span><span>' + escapeHtmlClient(entry.message || "-") + '</span></div>').join("") || '<div class="muted">Aucune activité enregistrée.</div>';
}

async function loadUsers() {
  const data = await api("/api/users");
  $("userList").innerHTML = data.users.map((user) => '<div class="data-row"><div class="data-row-main"><strong>' + escapeHtmlClient(user.username) + '</strong><span class="muted">' + (user.role === "admin" ? "Administrateur" : "Lecture seule") + ' · 2FA ' + (user.totpEnabled ? "activée" : "désactivée") + '</span></div><div class="actions">' + (user.totpEnabled ? '<button data-disable-totp="' + escapeHtmlClient(user.username) + '"><i data-lucide="shield-off"></i>Désactiver 2FA</button>' : '<button data-user-totp="' + escapeHtmlClient(user.username) + '"><i data-lucide="shield-check"></i>Activer 2FA</button>') + (user.username === currentUser.username ? '' : '<button class="danger-icon" data-delete-user="' + escapeHtmlClient(user.username) + '" title="Supprimer"><i data-lucide="trash-2"></i></button>') + '</div></div>').join("");
  document.querySelectorAll("[data-user-totp]").forEach((button) => { button.onclick = () => setupTotp(button.dataset.userTotp); });
  document.querySelectorAll("[data-disable-totp]").forEach((button) => { button.onclick = () => disableTotp(button.dataset.disableTotp); });
  document.querySelectorAll("[data-delete-user]").forEach((button) => { button.onclick = () => deleteUser(button.dataset.deleteUser); });
  lucide.createIcons();
  applyRole();
}

async function setupTotp(username) {
  const setup = await api("/api/users/" + encodeURIComponent(username) + "/totp/setup", { method:"POST", body:"{}" });
  const token = await requestTextInput("Activer la 2FA", "Clé " + setup.secret + " · code à 6 chiffres");
  if (!token) return;
  await api("/api/users/" + encodeURIComponent(username) + "/totp/enable", { method:"POST", body:JSON.stringify({ token }) });
  toast("Authentification à deux facteurs activée.");
  await loadUsers();
}

async function deleteUser(username) {
  if (!await requireTypedConfirmation("Le compte ne pourra plus se connecter.", username, "Supprimer le compte")) return;
  await api("/api/users/" + encodeURIComponent(username), { method:"DELETE", body:"{}" });
  await loadUsers();
}

async function disableTotp(username) {
  if (!await requireTypedConfirmation("La connexion ne demandera plus de second facteur.", username, "Désactiver la 2FA")) return;
  await api("/api/users/" + encodeURIComponent(username) + "/totp", { method:"DELETE", body:"{}" });
  toast("Authentification à deux facteurs désactivée.");
  await loadUsers();
}

function renderFiles() {
  const search = $("fileSearch").value.trim().toLowerCase();
  const files = currentFiles.filter((file) => !search || file.name.toLowerCase().includes(search));
  $("fileList").innerHTML = files.map((file) => {
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

function renderBreadcrumbs() {
  const parts = currentFilePath.split("/").filter(Boolean);
  const crumbs = [{ name:"Racine", path:"" }];
  parts.forEach((name, index) => crumbs.push({ name, path: parts.slice(0, index + 1).join("/") }));
  $("fileBreadcrumbs").innerHTML = crumbs.map((crumb) => '<button data-breadcrumb="' + escapeHtmlClient(crumb.path) + '">' + escapeHtmlClient(crumb.name) + '</button>').join("");
  document.querySelectorAll("[data-breadcrumb]").forEach((button) => {
    button.onclick = () => loadFiles(button.dataset.breadcrumb).catch((error) => toast(error.message, "error"));
  });
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
  if (!activeId && !options.allowNoActive) return;
  try {
    await fn();
    toast(label);
    await refreshServers();
  } catch (error) {
    toast(error.message, "error");
  } finally {
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
$("navServers").onclick = () => showOverview();
$("navAccounts").onclick = () => showAccounts();
document.querySelectorAll("[data-tab]").forEach((button) => {
  button.onclick = () => setDetailTab(button.dataset.tab);
});
$("moreTab").onchange = () => { if ($("moreTab").value) setDetailTab($("moreTab").value); };
$("refreshLogs").onclick = () => refreshLogs().catch((error) => toast(error.message));
$("startBtn").onclick = () => action("Serveur démarré.", () => api(endpoint("/start"), { method:"POST" }));
$("stopBtn").onclick = () => action("Serveur arrêté.", () => api(endpoint("/stop"), { method:"POST" }));
$("restartBtn").onclick = () => action("Serveur redémarré.", () => api(endpoint("/restart"), { method:"POST" }));
$("installServer").onclick = () => action("Installation terminée.", () => api(endpoint("/install"), { method:"POST", body:"{}" }));
$("updateServer").onclick = async () => {
  if (!await requireTypedConfirmation("Une sauvegarde sera créée avant la mise à jour.", "REINSTALL", "Mettre à jour Bedrock")) return;
  action("Mise à jour terminée.", () => api(endpoint("/reinstall"), { method:"POST", body: JSON.stringify({ confirm: "REINSTALL" }) }));
};
$("checkVersion").onclick = async () => {
  try {
    const data = await api(endpoint("/version"));
    $("serverVersion").textContent = data.installed + (data.latest !== "Inconnue" ? " / " + data.latest : "");
    toast("Installée: " + data.installed + " · Disponible: " + data.latest + (data.updateAvailable ? " · Mise à jour disponible" : ""));
  } catch (error) { toast(error.message, "error"); }
};
$("chooseBinary").onclick = () => $("binaryUpload").click();
$("binaryUpload").onchange = async () => {
  const file = $("binaryUpload").files[0];
  if (!file) return;
  const body = new FormData();
  body.append("file", file);
  await action("Binaire importé.", () => api(endpoint("/binary"), { method:"POST", body }));
  $("binaryUpload").value = "";
};
$("copyAddress").onclick = async () => {
  await navigator.clipboard.writeText($("serverAddress").textContent);
  toast("Adresse copiée.");
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
$("logSearch").oninput = renderLogs;
$("logFilter").onchange = renderLogs;
$("createBackup").onclick = () => action("Sauvegarde créée.", () => api(endpoint("/backups"), { method:"POST" }));
$("saveBackupPolicy").onclick = () => action("Planification enregistrée.", () => api(endpoint(""), { method:"PATCH", body:JSON.stringify({ backupPolicy:{ enabled:$("backupEnabled").value === "true", intervalMinutes:Number($("backupInterval").value), retention:Number($("backupRetention").value) } }) }));
$("saveProperties").onclick = () => action("Configuration enregistrée.", () => api(endpoint("/properties-form"), { method:"PUT", body: JSON.stringify({ values: collectPropertyForm() }) }));
$("saveServer").onclick = () => action("Serveur modifié.", () => api(endpoint(""), {
  method:"PATCH",
  body: JSON.stringify({
    name: $("serverName").value,
    port: $("serverPort").value,
    autoStart: $("serverAutoStart").checked
  })
}));
$("savePerformance").onclick = () => action("Performances enregistrées. Redémarre le serveur pour appliquer les changements.", () => api(endpoint(""), {
  method:"PATCH",
  body:JSON.stringify({ resources:collectPerformanceForm() })
}));
$("performanceProfile").onchange = () => {
  const profile = $("performanceProfile").value;
  setPerformanceForm({ performanceProfile:profile, ...(PERFORMANCE_PRESETS[profile] || collectPerformanceForm()) });
};
["resourceRam", "resourceCpu", "resourceStorage", "resourceViewDistance", "resourceTickDistance"].forEach((id) => {
  $(id).oninput = () => { $("performanceProfile").value = "custom"; $("performanceBadge").textContent = "Personnalisé"; };
});
$("deleteServer").onclick = () => {
  const server = activeServer();
  if (!server) return;
  deleteServerById(server.id);
};

$("refreshPlayers").onclick = () => loadPlayers().catch((error) => toast(error.message, "error"));
$("addAllowlist").onclick = async () => {
  const name = $("allowlistName").value.trim();
  if (!name) return;
  await saveAllowlist([...playerState.allowlist, { name, ignoresPlayerLimit:false }]);
  $("allowlistName").value = "";
};
$("addPermission").onclick = async () => {
  const xuid = $("permissionXuid").value.trim();
  if (!xuid) return;
  await savePermissions([...playerState.permissions.filter((entry) => entry.xuid !== xuid), { xuid, permission:$("permissionRole").value }]);
  $("permissionXuid").value = "";
};
$("chooseWorldImport").onclick = () => $("worldImport").click();
$("worldImport").onchange = async () => {
  const file = $("worldImport").files[0];
  if (!file) return;
  const body = new FormData();
  body.append("file", file);
  await action("Monde importé.", () => api(endpoint("/worlds/import"), { method:"POST", body }));
  $("worldImport").value = "";
  await loadWorlds();
};
$("refreshActivity").onclick = () => loadActivity().catch((error) => toast(error.message, "error"));
$("createUser").onclick = async () => {
  try {
    await api("/api/users", { method:"POST", body:JSON.stringify({ username:$("newUsername").value, password:$("newUserPassword").value, role:$("newUserRole").value }) });
    $("newUsername").value = "";
    $("newUserPassword").value = "";
    toast("Compte créé.");
    await loadUsers();
  } catch (error) { toast(error.message, "error"); }
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
$("fileSearch").oninput = renderFiles;
$("chooseFileUpload").onclick = () => $("fileUpload").click();
$("fileUpload").onchange = async () => {
  const file = $("fileUpload").files[0];
  if (!file) return;
  const body = new FormData();
  body.append("file", file);
  body.append("path", currentFilePath);
  try {
    await api(endpoint("/files/upload"), { method:"POST", body });
  } catch (error) {
    if (!/déjà ce nom/i.test(error.message) || !await requireTypedConfirmation("Le fichier existant sera remplacé.", file.name, "Écraser le fichier")) throw error;
    body.set("overwrite", "true");
    await api(endpoint("/files/upload"), { method:"POST", body });
  }
  $("fileUpload").value = "";
  toast("Fichier importé.");
  await loadFiles(currentFilePath);
};
$("renameFile").onclick = async () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.", "error");
  const name = await requestTextInput("Renommer", "Nouveau nom");
  if (!name) return;
  const data = await api(endpoint("/file"), { method:"PATCH", body:JSON.stringify({ path:selectedFilePath, name }) });
  selectedFilePath = data.file.path;
  $("fileEditorPath").value = selectedFilePath;
  await loadFiles(currentFilePath);
};
$("downloadFile").onclick = () => {
  if (!selectedFilePath) return toast("Sélectionne un fichier.", "error");
  window.location.assign(endpoint("/file/download?path=") + encodeURIComponent(selectedFilePath));
};
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
Promise.all([loadCurrentUser(), refreshServers()]).catch((error) => toast(error.message, "error"));
setInterval(() => {
  if (viewMode === "detail" && activeId) {
    refreshActive().catch(() => {});
  } else {
    refreshServers().catch(() => {});
  }
}, 10000);
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

async function loadOrCreateRuntimeSecrets(file) {
  await fsp.mkdir(path.dirname(file), { recursive:true });
  try {
    const saved = JSON.parse(await fsp.readFile(file, "utf8"));
    if (saved.adminPassword && saved.sessionSecret) return { ...saved, created:false };
  } catch (error) {
    if (error.code !== "ENOENT") console.warn(`Secrets locaux illisibles, regeneration: ${error.message}`);
  }
  const secrets = {
    adminPassword:crypto.randomBytes(18).toString("base64url"),
    sessionSecret:crypto.randomBytes(48).toString("hex")
  };
  const temporary = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(temporary, JSON.stringify(secrets, null, 2), { encoding:"utf8", mode:0o600 });
  await fsp.rename(temporary, file);
  return { ...secrets, created:true };
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
