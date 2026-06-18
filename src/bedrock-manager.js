import archiver from "archiver";
import unzipper from "unzipper";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import { pipeline } from "node:stream/promises";

const BEDROCK_FOLDERS = [
  "behavior_packs",
  "config",
  "data",
  "definitions",
  "development_behavior_packs",
  "development_resource_packs",
  "development_skin_packs",
  "resource_packs",
  "worlds",
  "world_templates"
];

const BEDROCK_FILES = [
  "allowlist.json",
  "permissions.json",
  "packetlimitconfig.json",
  "profanity_filter.wlist",
  "server.properties"
];

const PROTECTED_ROOT_NAMES = new Set([
  ".codex",
  ".git",
  ".gitignore",
  ".dockerignore",
  ".env",
  ".env.example",
  ".panel",
  "node_modules",
  "src",
  "package.json",
  "package-lock.json",
  "Dockerfile",
  "railway.json",
  "README_RAILWAY.md",
  "panel.out.log",
  "panel.err.log"
]);

export class BedrockManager {
  constructor(options) {
    this.rootDir = options.rootDir;
    this.serverDir = path.resolve(options.serverDir || defaultServerDir(options.rootDir));
    this.seedDir = path.resolve(options.seedDir || process.env.SEED_DIR || options.rootDir);
    this.backupDir = path.resolve(options.backupDir || path.join(this.serverDir, "backups"));
    this.downloadUrl = options.downloadUrl || "";
    this.autoStart = options.autoStart;
    this.child = null;
    this.startedAt = null;
    this.manualStop = false;
    this.logLines = [];
    this.maxLogs = 1200;
    this.logWaiters = [];
  }

  async status() {
    const backups = await this.listBackups();
    return {
      running: this.isRunning(),
      uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
      gamePort: await this.readProperty("server-port"),
      hostIps: localAddresses(),
      worldName: await this.worldName(),
      backupCount: backups.length,
      serverDir: this.serverDir,
      backupDir: this.backupDir
    };
  }

  logs(limit = 300) {
    return this.logLines.slice(-Math.max(1, Math.min(limit, this.maxLogs)));
  }

  isRunning() {
    return Boolean(this.child && !this.child.killed && this.child.exitCode === null);
  }

  async start() {
    if (this.isRunning()) return;
    this.manualStop = false;
    await this.prepare();
    const executable = this.executablePath();
    await assertExists(executable, `Binaire Bedrock introuvable: ${executable}`);
    const env = {
      ...process.env,
      LD_LIBRARY_PATH: [this.serverDir, process.env.LD_LIBRARY_PATH].filter(Boolean).join(":")
    };
    this.appendLog(`[panel] Demarrage du serveur depuis ${this.serverDir}\n`);
    this.child = spawn(executable, [], {
      cwd: this.serverDir,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    this.startedAt = Date.now();
    this.child.stdout.on("data", (chunk) => this.appendLog(chunk.toString()));
    this.child.stderr.on("data", (chunk) => this.appendLog(chunk.toString()));
    this.child.on("exit", (code, signal) => {
      this.appendLog(`[panel] Serveur arrete (code=${code ?? "null"}, signal=${signal ?? "null"})\n`);
      this.startedAt = null;
      if (!this.manualStop && this.autoStart) {
        setTimeout(() => this.start().catch((error) => this.appendLog(`[panel] Redemarrage impossible: ${error.message}\n`)), 5000);
      }
    });
  }

  async stop(timeoutMs = 15000) {
    if (!this.isRunning()) return;
    this.manualStop = true;
    this.appendLog("[panel] Arret demande\n");
    this.sendCommand("stop");
    await waitForExit(this.child, timeoutMs).catch(() => {
      if (this.isRunning()) {
        this.appendLog("[panel] Arret force\n");
        this.child.kill("SIGTERM");
      }
    });
  }

  async restart() {
    await this.stop();
    await this.start();
  }

  sendCommand(command) {
    if (!this.isRunning()) {
      throw new Error("Le serveur n'est pas demarre.");
    }
    this.child.stdin.write(`${command}\n`);
    this.appendLog(`[commande] ${command}\n`);
  }

  async reinstall() {
    const wasRunning = this.isRunning();
    const backup = await this.createBackup();
    await this.stop();
    await this.installBedrock(true);
    if (wasRunning || this.autoStart) {
      await this.start();
    }
    return { backup };
  }

  async prepare() {
    await fsp.mkdir(this.serverDir, { recursive: true });
    await fsp.mkdir(this.backupDir, { recursive: true });
    await this.seedInitialFiles();
    if (!(await exists(this.executablePath()))) {
      if (process.platform === "win32" && (await exists(path.join(this.serverDir, "bedrock_server.exe")))) {
        return;
      }
      await this.installBedrock(false);
    }
  }

  async seedInitialFiles() {
    const hasProperties = await exists(path.join(this.serverDir, "server.properties"));
    const sameDir = path.resolve(this.seedDir) === path.resolve(this.serverDir);
    if (hasProperties || sameDir || !(await exists(this.seedDir))) return;
    this.appendLog(`[panel] Copie des donnees initiales depuis ${this.seedDir}\n`);
    for (const folder of BEDROCK_FOLDERS) {
      await copyIfExists(path.join(this.seedDir, folder), path.join(this.serverDir, folder));
    }
    for (const file of BEDROCK_FILES) {
      await copyIfExists(path.join(this.seedDir, file), path.join(this.serverDir, file));
    }
    if (process.platform === "win32") {
      await copyIfExists(path.join(this.seedDir, "bedrock_server.exe"), path.join(this.serverDir, "bedrock_server.exe"));
    } else {
      await copyIfExists(path.join(this.seedDir, "bedrock_server"), path.join(this.serverDir, "bedrock_server"));
    }
  }

  async installBedrock(force) {
    if (!force && (await exists(this.executablePath()))) return;
    if (process.platform === "win32") {
      throw new Error("Telechargement automatique prevu pour Linux. Garde bedrock_server.exe pour le local Windows.");
    }
    const url = this.downloadUrl || (await resolveLatestBedrockUrl());
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-install-"));
    const zipPath = path.join(tmpDir, "bedrock.zip");
    const extractDir = path.join(tmpDir, "extract");
    await fsp.mkdir(extractDir, { recursive: true });
    this.appendLog(`[panel] Telechargement Bedrock Linux: ${url}\n`);
    await downloadFile(url, zipPath);
    await extractZip(zipPath, extractDir);
    await copyDirectory(extractDir, this.serverDir, {
      excludeRootNames: new Set(["worlds", "allowlist.json", "permissions.json"])
    });
    await fsp.chmod(this.executablePath(), 0o755).catch(() => {});
    await fsp.rm(tmpDir, { recursive: true, force: true });
    this.appendLog("[panel] Installation Bedrock terminee\n");
  }

  executablePath() {
    return path.join(this.serverDir, process.platform === "win32" ? "bedrock_server.exe" : "bedrock_server");
  }

  async readProperties() {
    const file = path.join(this.serverDir, "server.properties");
    return exists(file) ? fsp.readFile(file, "utf8") : "";
  }

  async writeProperties(content) {
    await fsp.mkdir(this.serverDir, { recursive: true });
    await fsp.writeFile(path.join(this.serverDir, "server.properties"), content.replace(/\r?\n/g, "\n"), "utf8");
  }

  async readProperty(name) {
    const content = await this.readProperties();
    const line = content.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
    return line ? line.slice(name.length + 1).trim() : "";
  }

  async worldName() {
    const worldFolder = await this.readProperty("level-name");
    const candidates = [
      worldFolder && path.join(this.serverDir, "worlds", worldFolder, "levelname.txt"),
      path.join(this.serverDir, "worlds", "Bedrock level", "levelname.txt")
    ].filter(Boolean);
    for (const candidate of candidates) {
      if (await exists(candidate)) {
        return (await fsp.readFile(candidate, "utf8")).trim();
      }
    }
    return worldFolder || "Bedrock level";
  }

  async createBackup() {
    await fsp.mkdir(this.backupDir, { recursive: true });
    let saveHeld = false;
    if (this.isRunning()) {
      this.child.stdin.write("save hold\n");
      saveHeld = true;
      await this.waitForLog(/ready to be copied|saving has been disabled|save hold|saved/i, 15000);
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `bedrock-backup-${stamp}.zip`;
    const target = path.join(this.backupDir, filename);
    try {
      await archivePaths(this.serverDir, target, [...BEDROCK_FOLDERS, ...BEDROCK_FILES]);
    } finally {
      if (saveHeld && this.isRunning()) {
        this.child.stdin.write("save resume\n");
      }
    }
    const stats = await fsp.stat(target);
    return { name: filename, size: stats.size, sizeLabel: formatBytes(stats.size), createdAt: stats.mtime.toISOString() };
  }

  async listBackups() {
    await fsp.mkdir(this.backupDir, { recursive: true });
    const entries = await fsp.readdir(this.backupDir, { withFileTypes: true });
    const backups = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".zip")) continue;
      const file = path.join(this.backupDir, entry.name);
      const stats = await fsp.stat(file);
      backups.push({ name: entry.name, size: stats.size, sizeLabel: formatBytes(stats.size), createdAt: stats.mtime.toISOString() });
    }
    return backups.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async resolveBackup(name) {
    const safeName = path.basename(name);
    if (safeName !== name || !safeName.endsWith(".zip")) {
      throw new Error("Nom de sauvegarde invalide.");
    }
    const file = path.join(this.backupDir, safeName);
    await assertExists(file, "Sauvegarde introuvable.");
    return file;
  }

  async restoreBackup(name) {
    const file = await this.resolveBackup(name);
    await this.stop();
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-restore-"));
    await extractZip(file, tmpDir);
    await copyDirectory(tmpDir, this.serverDir, { excludeRootNames: new Set(["backups"]) });
    await fsp.rm(tmpDir, { recursive: true, force: true });
    if (this.autoStart) {
      await this.start();
    }
  }

  async deleteBackup(name) {
    await fsp.rm(await this.resolveBackup(name), { force: true });
  }

  async listFiles(relativePath = "") {
    const dir = this.resolveServerPath(relativePath);
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    const rows = [];
    for (const entry of entries) {
      if (path.resolve(dir) === path.resolve(this.serverDir) && PROTECTED_ROOT_NAMES.has(entry.name)) continue;
      const file = path.join(dir, entry.name);
      const stats = await fsp.stat(file);
      rows.push({
        name: entry.name,
        path: toPosix(path.relative(this.serverDir, file)),
        type: entry.isDirectory() ? "directory" : "file",
        size: stats.size,
        sizeLabel: formatBytes(stats.size),
        modifiedAt: stats.mtime.toISOString()
      });
    }
    return rows.sort((a, b) => {
      if (a.type !== b.type) return a.type === "directory" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }

  async readFile(relativePath) {
    const file = this.resolveServerPath(relativePath);
    const stats = await fsp.stat(file);
    if (!stats.isFile()) throw new Error("Ce chemin n'est pas un fichier.");
    if (stats.size > 1024 * 1024) throw new Error("Fichier trop volumineux pour l'editeur.");
    return fsp.readFile(file, "utf8");
  }

  async writeFile(relativePath, content) {
    const file = this.resolveServerPath(relativePath);
    await fsp.mkdir(path.dirname(file), { recursive: true });
    await fsp.writeFile(file, String(content || ""), "utf8");
  }

  async makeDirectory(relativePath) {
    await fsp.mkdir(this.resolveServerPath(relativePath), { recursive: true });
  }

  async deleteFile(relativePath) {
    const target = this.resolveServerPath(relativePath);
    if (path.resolve(target) === path.resolve(this.serverDir)) {
      throw new Error("Impossible de supprimer la racine du serveur.");
    }
    await fsp.rm(target, { recursive: true, force: true });
  }

  resolveServerPath(relativePath = "") {
    const normalized = path.normalize(String(relativePath || ".")).replace(/^(\.\.[/\\])+/, "");
    if (path.isAbsolute(normalized) || normalized.includes("..")) {
      throw new Error("Chemin invalide.");
    }
    const rootName = normalized.split(/[\\/]/).filter(Boolean)[0];
    if (rootName && PROTECTED_ROOT_NAMES.has(rootName)) {
      throw new Error("Ce fichier appartient au panel et n'est pas editable ici.");
    }
    const target = path.resolve(this.serverDir, normalized);
    if (target !== path.resolve(this.serverDir) && !isInside(this.serverDir, target)) {
      throw new Error("Chemin hors du serveur.");
    }
    return target;
  }

  appendLog(text) {
    const parts = text.split(/(?<=\n)/);
    this.logLines.push(...parts.filter(Boolean));
    if (this.logLines.length > this.maxLogs) {
      this.logLines.splice(0, this.logLines.length - this.maxLogs);
    }
    for (const line of parts) {
      for (const waiter of [...this.logWaiters]) {
        if (waiter.pattern.test(line)) waiter.resolve(line);
      }
    }
    this.logWaiters = this.logWaiters.filter((waiter) => !waiter.done);
  }

  waitForLog(pattern, timeoutMs) {
    return new Promise((resolve, reject) => {
      const waiter = {
        pattern,
        done: false,
        resolve: (line) => {
          waiter.done = true;
          clearTimeout(timer);
          resolve(line);
        }
      };
      const timer = setTimeout(() => {
        waiter.done = true;
        reject(new Error("Le serveur n'a pas confirme la pause des sauvegardes a temps."));
      }, timeoutMs);
      this.logWaiters.push(waiter);
    });
  }
}

function defaultServerDir(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/bedrock";
  }
  return path.join(rootDir, "servers", "principal");
}

async function resolveLatestBedrockUrl() {
  const page = await fetch("https://www.minecraft.net/en-us/download/server/bedrock", {
    headers: { "User-Agent": "Mozilla/5.0 bedrock-railway-panel" }
  });
  if (!page.ok) {
    throw new Error(`Page de telechargement Minecraft inaccessible (${page.status}).`);
  }
  const html = await page.text();
  const match = html.match(/https:\/\/www\.minecraft\.net\/bedrockdedicatedserver\/bin-linux\/bedrock-server-[^"']+\.zip/);
  if (!match) {
    throw new Error("Lien Linux Bedrock introuvable. Definis BDS_DOWNLOAD_URL dans Railway.");
  }
  return match[0].replaceAll("&amp;", "&");
}

async function downloadFile(url, target) {
  const response = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 bedrock-railway-panel" } });
  if (!response.ok || !response.body) {
    throw new Error(`Telechargement impossible (${response.status}).`);
  }
  await pipeline(response.body, fs.createWriteStream(target));
}

async function extractZip(zipPath, destination) {
  const directory = await unzipper.Open.file(zipPath);
  for (const entry of directory.files) {
    const safePath = safeRelativePath(entry.path);
    if (!safePath) continue;
    const target = path.join(destination, safePath);
    if (entry.type === "Directory") {
      await fsp.mkdir(target, { recursive: true });
      continue;
    }
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await pipeline(entry.stream(), fs.createWriteStream(target));
  }
}

async function archivePaths(baseDir, target, names) {
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(target);
    const archive = archiver("zip", { zlib: { level: 9 } });
    output.on("close", resolve);
    archive.on("error", reject);
    archive.pipe(output);
    for (const name of names) {
      const source = path.join(baseDir, name);
      if (!fs.existsSync(source)) continue;
      const stats = fs.statSync(source);
      if (stats.isDirectory()) archive.directory(source, name);
      if (stats.isFile()) archive.file(source, { name });
    }
    archive.finalize();
  });
}

async function copyIfExists(source, target) {
  if (!(await exists(source))) return;
  await copyDirectory(source, target);
}

async function copyDirectory(source, target, options = {}) {
  const stats = await fsp.stat(source);
  if (stats.isFile()) {
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.copyFile(source, target);
    return;
  }
  await fsp.mkdir(target, { recursive: true });
  const entries = await fsp.readdir(source, { withFileTypes: true });
  for (const entry of entries) {
    if (options.excludeRootNames?.has(entry.name)) continue;
    const from = path.join(source, entry.name);
    const to = path.join(target, entry.name);
    if (entry.isDirectory()) {
      await copyDirectory(from, to);
    } else if (entry.isFile()) {
      await fsp.mkdir(path.dirname(to), { recursive: true });
      await fsp.copyFile(from, to);
    }
  }
}

function safeRelativePath(input) {
  const normalized = path.normalize(input).replace(/^(\.\.[/\\])+/, "");
  if (path.isAbsolute(normalized) || normalized.includes("..")) return "";
  return normalized;
}

async function assertExists(file, message) {
  if (!(await exists(file))) throw new Error(message);
}

async function exists(file) {
  return fsp.access(file).then(() => true).catch(() => false);
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout")), timeoutMs);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  const units = ["Ko", "Mo", "Go"];
  let value = bytes / 1024;
  let unit = units.shift();
  while (value >= 1024 && units.length) {
    value /= 1024;
    unit = units.shift();
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${unit}`;
}

function localAddresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const values of Object.values(interfaces)) {
    for (const value of values || []) {
      if (value.family === "IPv4" && !value.internal) addresses.push(value.address);
    }
  }
  return addresses;
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function isInside(parent, child) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
