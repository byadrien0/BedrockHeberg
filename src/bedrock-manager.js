import archiver from "archiver";
import unzipper from "unzipper";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import dgram from "node:dgram";
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
  ".bedrock-version",
  ".bedrock-panel-state.json",
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
    this.eventListeners = new Set();
    this.operationQueue = Promise.resolve();
    this.pendingOperations = 0;
    this.queuedOperationTypes = new Set();
    this.operation = { type: "idle", progress: 0, startedAt: null };
    this.lastError = "";
    this.commandHistory = [];
    this.detectedVersion = "";
    this.cachedDiskUsage = { value: 0, measuredAt: 0 };
    this.persistentState = { firstStartedAt: "", lastError: "", version: "" };
    this.stateLoaded = false;
  }

  async status() {
    await this.loadPersistentState();
    const backups = await this.listBackups();
    const installed = await exists(this.executablePath());
    const gamePort = await this.readProperty("server-port");
    const port = Number(gamePort || 19132);
    const network = await this.networkStatus(port);
    return {
      running: this.isRunning(),
      uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
      gamePort,
      hostIps: localAddresses(),
      worldName: await this.worldName(),
      backupCount: backups.length,
      lastBackup: backups[0] || null,
      serverDir: this.serverDir,
      backupDir: this.backupDir,
      installed,
      installationState: this.installationState(installed),
      lifecycle: this.lifecycleState(installed),
      firstStartedAt: this.persistentState.firstStartedAt,
      operation: { ...this.operation, pending: this.pendingOperations },
      lastError: this.lastError || this.persistentState.lastError,
      version: await this.installedVersion(),
      diskUsageBytes: await this.diskUsage(),
      diskUsageLabel: formatBytes(await this.diskUsage()),
      network
    };
  }

  installationState(installed) {
    if (["installing", "updating", "reinstalling"].includes(this.operation.type)) return "installing";
    if (installed) return "ready";
    return this.lastError ? "error" : "not-installed";
  }

  lifecycleState(installed) {
    const error = this.lastError || this.persistentState.lastError;
    if (error && !this.persistentState.firstStartedAt) return "error";
    if (!installed) return "created";
    if (["starting", "installing", "updating"].includes(this.operation.type) && !this.persistentState.firstStartedAt) return "initializing";
    if (!this.persistentState.firstStartedAt) return "installed";
    return "operational";
  }

  async runOperation(type, task) {
    if (this.operation.type === type || this.queuedOperationTypes.has(type)) throw new Error("Cette opération est déjà en cours ou en attente.");
    this.queuedOperationTypes.add(type);
    this.pendingOperations += 1;
    const run = async () => {
      this.queuedOperationTypes.delete(type);
      this.pendingOperations -= 1;
      this.operation = { type, progress: 0, startedAt: new Date().toISOString() };
      this.lastError = "";
      this.emitEvent("operation", { operation: { ...this.operation }, pending: this.pendingOperations });
      try {
        const result = await task((progress) => this.setProgress(progress));
        this.setProgress(100);
        if (["installing", "updating", "starting"].includes(type)) {
          this.persistentState.lastError = "";
          await this.savePersistentState().catch(() => {});
        }
        return result;
      } catch (error) {
        this.lastError = error.message || "Erreur inconnue";
        this.persistentState.lastError = this.lastError;
        await this.savePersistentState().catch(() => {});
        this.emitEvent("error", { message: this.lastError, operation: type });
        throw error;
      } finally {
        this.operation = { type: "idle", progress: 0, startedAt: null };
        this.emitEvent("operation", { operation: { ...this.operation }, pending: this.pendingOperations });
      }
    };
    const queued = this.operationQueue.catch(() => {}).then(run);
    this.operationQueue = queued;
    return queued;
  }

  setProgress(progress) {
    this.operation.progress = Math.max(0, Math.min(100, Number(progress) || 0));
    this.emitEvent("operation", { operation: { ...this.operation }, pending: this.pendingOperations });
  }

  subscribe(listener) {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  emitEvent(type, data) {
    for (const listener of this.eventListeners) listener({ type, data, at: new Date().toISOString() });
  }

  logs(limit = 300) {
    return this.logLines.slice(-Math.max(1, Math.min(limit, this.maxLogs)));
  }

  isRunning() {
    return Boolean(this.child && !this.child.killed && this.child.exitCode === null);
  }

  async start() {
    if (this.isRunning()) return;
    await this.loadPersistentState();
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
    this.child.on("error", (error) => {
      this.lastError = error.message;
      this.persistentState.lastError = error.message;
      this.appendLog(`[panel] Echec du processus Bedrock: ${error.message}\n`);
      this.savePersistentState().catch(() => {});
    });
    this.child.on("exit", (code, signal) => {
      this.appendLog(`[panel] Serveur arrete (code=${code ?? "null"}, signal=${signal ?? "null"})\n`);
      this.startedAt = null;
      if (!this.manualStop && this.autoStart) {
        setTimeout(() => this.start().catch((error) => this.appendLog(`[panel] Redemarrage impossible: ${error.message}\n`)), 5000);
      }
    });
    await Promise.race([
      this.waitForLog(/server started|ipv4 supported|server is running/i, 60000, "Bedrock n'a pas confirmé son démarrage dans le délai prévu."),
      new Promise((_, reject) => {
        this.child.once("error", reject);
        this.child.once("exit", (code) => reject(new Error(`Bedrock s'est arrêté pendant le démarrage (code ${code ?? "inconnu"}).`)));
      })
    ]);
    if (!this.persistentState.firstStartedAt) this.persistentState.firstStartedAt = new Date().toISOString();
    this.persistentState.lastError = "";
    this.lastError = "";
    await this.savePersistentState();
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
    this.commandHistory.push({ command, createdAt: new Date().toISOString() });
    if (this.commandHistory.length > 100) this.commandHistory.shift();
  }

  recentCommands() {
    return [...this.commandHistory].reverse();
  }

  async reinstall(reportProgress = () => {}) {
    const wasRunning = this.isRunning();
    reportProgress(5);
    const backup = await this.createBackup("update");
    reportProgress(20);
    await this.stop();
    reportProgress(30);
    await this.installBedrock(true, (progress) => reportProgress(30 + Math.round(progress * 0.65)));
    if (wasRunning || this.autoStart) {
      await this.start();
    }
    reportProgress(100);
    return { backup };
  }

  async prepare(options = {}) {
    await fsp.mkdir(this.serverDir, { recursive: true });
    await fsp.mkdir(this.backupDir, { recursive: true });
    await this.seedInitialFiles();
    if (!(await exists(this.executablePath()))) {
      if (process.platform === "win32" && (await exists(path.join(this.serverDir, "bedrock_server.exe")))) {
        return;
      }
      if (process.platform === "win32" && options.allowMissingExecutable) return;
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

  async installBedrock(force, reportProgress = () => {}) {
    if (!force && (await exists(this.executablePath()))) return;
    const url = this.downloadUrl || (await resolveLatestBedrockUrl());
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-install-"));
    const zipPath = path.join(tmpDir, "bedrock.zip");
    const extractDir = path.join(tmpDir, "extract");
    await fsp.mkdir(extractDir, { recursive: true });
    const platformName = process.platform === "win32" ? "Windows" : "Linux";
    this.appendLog(`[panel] Telechargement Bedrock ${platformName}: ${url}\n`);
    reportProgress(10);
    await downloadFile(url, zipPath);
    reportProgress(55);
    await extractZip(zipPath, extractDir);
    reportProgress(75);
    await copyDirectory(extractDir, this.serverDir, {
      excludeRootNames: new Set(["worlds", "allowlist.json", "permissions.json"])
    });
    await fsp.chmod(this.executablePath(), 0o755).catch(() => {});
    const version = versionFromUrl(url);
    if (version) await fsp.writeFile(path.join(this.serverDir, ".bedrock-version"), version, "utf8");
    await fsp.rm(tmpDir, { recursive: true, force: true });
    reportProgress(100);
    this.appendLog("[panel] Installation Bedrock terminee\n");
  }

  executablePath() {
    return path.join(this.serverDir, process.platform === "win32" ? "bedrock_server.exe" : "bedrock_server");
  }

  async readProperties() {
    const file = path.join(this.serverDir, "server.properties");
    try {
      return await fsp.readFile(file, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return "";
      throw error;
    }
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

  async createBackup(origin = "manual") {
    await fsp.mkdir(this.backupDir, { recursive: true });
    let saveHeld = false;
    if (this.isRunning()) {
      this.child.stdin.write("save hold\n");
      saveHeld = true;
      await this.waitForLog(/ready to be copied|saving has been disabled|save hold|saved/i, 15000);
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const safeOrigin = ["manual", "automatic", "update"].includes(origin) ? origin : "manual";
    const filename = `bedrock-${safeOrigin}-${stamp}.zip`;
    const target = path.join(this.backupDir, filename);
    try {
      await archivePaths(this.serverDir, target, [...BEDROCK_FOLDERS, ...BEDROCK_FILES]);
    } finally {
      if (saveHeld && this.isRunning()) {
        this.child.stdin.write("save resume\n");
      }
    }
    const stats = await fsp.stat(target);
    return { name: filename, origin: safeOrigin, size: stats.size, sizeLabel: formatBytes(stats.size), createdAt: stats.mtime.toISOString() };
  }

  async listBackups() {
    await fsp.mkdir(this.backupDir, { recursive: true });
    const entries = await fsp.readdir(this.backupDir, { withFileTypes: true });
    const backups = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".zip")) continue;
      const file = path.join(this.backupDir, entry.name);
      const stats = await fsp.stat(file);
      backups.push({ name: entry.name, origin: backupOrigin(entry.name), size: stats.size, sizeLabel: formatBytes(stats.size), createdAt: stats.mtime.toISOString() });
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

  async enforceBackupRetention(maxBackups) {
    const limit = Math.max(1, Math.min(100, Number(maxBackups) || 10));
    const backups = await this.listBackups();
    for (const backup of backups.slice(limit)) await this.deleteBackup(backup.name);
  }

  async installedVersion() {
    if (this.detectedVersion) return this.detectedVersion;
    try {
      return (await fsp.readFile(path.join(this.serverDir, ".bedrock-version"), "utf8")).trim();
    } catch (error) {
      if (error.code === "ENOENT") return "Inconnue";
      throw error;
    }
  }

  async loadPersistentState() {
    if (this.stateLoaded) return;
    try {
      const state = JSON.parse(await fsp.readFile(this.stateFile(), "utf8"));
      this.persistentState = {
        firstStartedAt: String(state.firstStartedAt || ""),
        lastError: String(state.lastError || ""),
        version: String(state.version || "")
      };
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    this.stateLoaded = true;
  }

  async savePersistentState() {
    await fsp.mkdir(this.serverDir, { recursive: true });
    await fsp.writeFile(this.stateFile(), JSON.stringify(this.persistentState, null, 2), "utf8");
  }

  stateFile() {
    return path.join(this.serverDir, ".bedrock-panel-state.json");
  }

  async latestVersionInfo() {
    const url = this.downloadUrl || (await resolveLatestBedrockUrl());
    const latest = versionFromUrl(url) || "Inconnue";
    const installed = await this.installedVersion();
    return { installed, latest, updateAvailable: installed !== "Inconnue" && latest !== "Inconnue" && installed !== latest };
  }

  async diskUsage() {
    if (Date.now() - this.cachedDiskUsage.measuredAt < 10000) return this.cachedDiskUsage.value;
    const value = await directorySize(this.serverDir).catch(() => 0);
    this.cachedDiskUsage = { value, measuredAt: Date.now() };
    return value;
  }

  async networkStatus(port) {
    const available = await udpPortAvailable(port);
    const publicHost = process.env.PUBLIC_IP || process.env.RAILWAY_PUBLIC_DOMAIN || "";
    return {
      localAddress: `${localAddresses()[0] || "127.0.0.1"}:${port}`,
      publicAddress: publicHost ? `${publicHost}:${port}` : "",
      udpState: this.isRunning() ? "expected-open" : (available ? "closed" : "in-use"),
      warning: !this.isRunning() ? "Le serveur est arrêté." : ""
    };
  }

  async listPlayers() {
    if (!this.isRunning()) return [];
    const offset = this.logLines.length;
    this.sendCommand("list");
    await delay(700);
    const output = this.logLines.slice(offset).join("");
    const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const marker = lines.findIndex((line) => /players online|joueurs en ligne/i.test(line));
    if (marker === -1) return [];
    const inline = lines[marker].split(":").slice(1).join(":").trim();
    const names = inline || lines[marker + 1] || "";
    return names.split(",").map((name) => name.trim()).filter(Boolean);
  }

  kickPlayer(name, reason = "Expulsé par un administrateur") {
    const safeName = String(name || "").replace(/[\r\n"]/g, "").trim();
    if (!safeName) throw new Error("Nom de joueur invalide.");
    this.sendCommand(`kick "${safeName}" ${String(reason || "").replace(/[\r\n]/g, " ")}`);
  }

  async allowlist() {
    return this.readJsonFile("allowlist.json", []);
  }

  async saveAllowlist(entries) {
    const rows = (Array.isArray(entries) ? entries : []).map((entry) => ({
      name: String(entry.name || "").trim(),
      ignoresPlayerLimit: Boolean(entry.ignoresPlayerLimit)
    })).filter((entry) => entry.name);
    await this.writeJsonFile("allowlist.json", rows);
    if (this.isRunning()) this.sendCommand("allowlist reload");
    return rows;
  }

  async permissions() {
    return this.readJsonFile("permissions.json", []);
  }

  async savePermissions(entries) {
    const allowed = new Set(["visitor", "member", "operator"]);
    const rows = (Array.isArray(entries) ? entries : []).map((entry) => ({
      permission: allowed.has(entry.permission) ? entry.permission : "member",
      xuid: String(entry.xuid || "").trim()
    })).filter((entry) => entry.xuid);
    await this.writeJsonFile("permissions.json", rows);
    if (this.isRunning()) this.sendCommand("permission reload");
    return rows;
  }

  async readJsonFile(name, fallback) {
    try {
      return JSON.parse(await fsp.readFile(path.join(this.serverDir, name), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return fallback;
      throw new Error(`${name} est invalide: ${error.message}`);
    }
  }

  async writeJsonFile(name, value) {
    await fsp.mkdir(this.serverDir, { recursive: true });
    await fsp.writeFile(path.join(this.serverDir, name), JSON.stringify(value, null, 2), "utf8");
  }

  async listWorlds() {
    const worldsDir = path.join(this.serverDir, "worlds");
    await fsp.mkdir(worldsDir, { recursive: true });
    const activeWorld = await this.readProperty("level-name");
    const entries = await fsp.readdir(worldsDir, { withFileTypes: true });
    const worlds = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const worldDir = path.join(worldsDir, entry.name);
      const stats = await fsp.stat(worldDir);
      const size = await directorySize(worldDir);
      worlds.push({
        name: entry.name,
        active: entry.name === activeWorld,
        size,
        sizeLabel: formatBytes(size),
        modifiedAt: stats.mtime.toISOString()
      });
    }
    return worlds.sort((a, b) => Number(b.active) - Number(a.active) || a.name.localeCompare(b.name));
  }

  async importWorld(archivePath, originalName = "monde.mcworld") {
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-world-import-"));
    try {
      await extractZip(archivePath, tmpDir);
      const entries = await fsp.readdir(tmpDir, { withFileTypes: true });
      let source = tmpDir;
      if (entries.length === 1 && entries[0].isDirectory()) source = path.join(tmpDir, entries[0].name);
      const levelName = await fsp.readFile(path.join(source, "levelname.txt"), "utf8").catch(() => "");
      const requested = levelName.trim() || path.basename(originalName, path.extname(originalName));
      const name = await uniqueDirectoryName(path.join(this.serverDir, "worlds"), safeWorldName(requested));
      await copyDirectory(source, path.join(this.serverDir, "worlds", name));
      return { name };
    } finally {
      await fsp.rm(tmpDir, { recursive: true, force: true });
    }
  }

  async exportWorld(name, target) {
    const safeName = safeWorldName(name);
    const worldDir = path.join(this.serverDir, "worlds", safeName);
    await assertExists(worldDir, "Monde introuvable.");
    await archivePaths(path.join(this.serverDir, "worlds"), target, [safeName]);
  }

  async duplicateWorld(name, newName) {
    const source = path.join(this.serverDir, "worlds", safeWorldName(name));
    await assertExists(source, "Monde introuvable.");
    const targetName = await uniqueDirectoryName(path.join(this.serverDir, "worlds"), safeWorldName(newName));
    await copyDirectory(source, path.join(this.serverDir, "worlds", targetName));
    return { name: targetName };
  }

  async activateWorld(name) {
    const safeName = safeWorldName(name);
    await assertExists(path.join(this.serverDir, "worlds", safeName), "Monde introuvable.");
    const wasRunning = this.isRunning();
    if (wasRunning) await this.stop();
    const content = await this.readProperties();
    await this.writeProperties(setPropertyValue(content, "level-name", safeName));
    if (wasRunning) await this.start();
    return { name:safeName };
  }

  async resetWorld(name) {
    const safeName = safeWorldName(name);
    const wasRunning = this.isRunning();
    if (wasRunning) await this.stop();
    await fsp.rm(path.join(this.serverDir, "worlds", safeName), { recursive: true, force: true });
    if (wasRunning) await this.start();
  }

  async restoreWorldFromBackup(backupName, worldName) {
    const backup = await this.resolveBackup(backupName);
    const safeName = safeWorldName(worldName);
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-world-restore-"));
    const wasRunning = this.isRunning();
    try {
      if (wasRunning) await this.stop();
      await extractZip(backup, tmpDir);
      const source = path.join(tmpDir, "worlds", safeName);
      await assertExists(source, "Ce monde n'existe pas dans la sauvegarde.");
      const target = path.join(this.serverDir, "worlds", safeName);
      await fsp.rm(target, { recursive: true, force: true });
      await copyDirectory(source, target);
    } finally {
      await fsp.rm(tmpDir, { recursive: true, force: true });
      if (wasRunning) await this.start();
    }
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

  async uploadFile(relativePath, temporaryFile, overwrite = false) {
    const target = this.resolveServerPath(relativePath);
    if (!overwrite && (await exists(target))) throw new Error("Un fichier porte déjà ce nom.");
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.copyFile(temporaryFile, target);
    return { path: toPosix(path.relative(this.serverDir, target)) };
  }

  async renameFile(relativePath, newName) {
    const source = this.resolveServerPath(relativePath);
    const safeName = path.basename(String(newName || "").trim());
    if (!safeName || safeName !== String(newName || "").trim()) throw new Error("Nouveau nom invalide.");
    const target = this.resolveServerPath(toPosix(path.join(path.dirname(relativePath), safeName)));
    if (await exists(target)) throw new Error("Un élément porte déjà ce nom.");
    await fsp.rename(source, target);
    return { path: toPosix(path.relative(this.serverDir, target)) };
  }

  async resolveDownload(relativePath) {
    const target = this.resolveServerPath(relativePath);
    const stats = await fsp.stat(target);
    if (!stats.isFile()) throw new Error("Ce chemin n'est pas un fichier.");
    return target;
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
    const versionMatch = text.match(/(?:version|Version)\s+([0-9]+(?:\.[0-9]+){2,3})/);
    if (versionMatch) this.detectedVersion = versionMatch[1];
    this.emitEvent("logs", { lines: parts.filter(Boolean) });
  }

  waitForLog(pattern, timeoutMs, timeoutMessage = "Le serveur n'a pas confirmé la pause des sauvegardes à temps.") {
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
        reject(new Error(timeoutMessage));
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

async function resolveLatestBedrockUrl(platform = process.platform) {
  const downloadType = platform === "win32" ? "serverBedrockWindows" : "serverBedrockLinux";
  try {
    const manifest = await fetch("https://net-secondary.web.minecraft-services.net/api/v1.0/download/links", {
      headers: { "User-Agent": "ServerAura/1.0" }
    });
    if (manifest.ok) {
      const url = bedrockDownloadUrlFromManifest(await manifest.json(), downloadType);
      if (url) return url;
    }
  } catch {
    // The public download page below remains a fallback when the manifest is unavailable.
  }

  const page = await fetch("https://www.minecraft.net/en-us/download/server/bedrock", {
    headers: { "User-Agent": "Mozilla/5.0 ServerAura" }
  });
  if (!page.ok) {
    throw new Error(`Page de telechargement Minecraft inaccessible (${page.status}).`);
  }
  const html = await page.text();
  const url = bedrockDownloadUrlFromHtml(html, platform);
  if (url) return url;
  const platformName = platform === "win32" ? "Windows" : "Linux";
  throw new Error(`Lien ${platformName} Bedrock introuvable. Reessaie plus tard ou importe le binaire manuellement.`);
}

export function bedrockDownloadUrlFromManifest(payload, downloadType) {
  const links = payload?.result?.links || payload?.links || [];
  return links.find((link) => link?.downloadType === downloadType)?.downloadUrl || "";
}

export function bedrockDownloadUrlFromHtml(html, platform = process.platform) {
  const directory = platform === "win32" ? "bin-win" : "bin-linux";
  const normalized = String(html || "").replaceAll("\\/", "/").replaceAll("&amp;", "&");
  const pattern = new RegExp(`https:\\/\\/www\\.minecraft\\.net\\/bedrockdedicatedserver\\/${directory}\\/bedrock-server-[^\"'\\s<]+\\.zip`, "i");
  return normalized.match(pattern)?.[0] || "";
}

async function downloadFile(url, target) {
  const response = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 ServerAura" } });
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

function backupOrigin(name) {
  const match = String(name).match(/^bedrock-(manual|automatic|update)-/);
  return match ? match[1] : "legacy";
}

function versionFromUrl(url) {
  return String(url).match(/bedrock-server-([0-9.]+)\.zip/i)?.[1] || "";
}

async function directorySize(directory) {
  if (!(await exists(directory))) return 0;
  let total = 0;
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) total += await directorySize(target);
    else if (entry.isFile()) total += (await fsp.stat(target)).size;
  }
  return total;
}

async function udpPortAvailable(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", () => {
      try { socket.close(); } catch {}
      resolve(false);
    });
    socket.bind(port, "0.0.0.0", () => {
      socket.close();
      resolve(true);
    });
  });
}

function safeWorldName(value) {
  const name = String(value || "Monde").trim().replace(/[<>:"/\\|?*\x00-\x1F]/g, "-").slice(0, 80);
  if (!name || name === "." || name === "..") throw new Error("Nom de monde invalide.");
  return name;
}

function setPropertyValue(content, key, value) {
  const lines = String(content || "").split(/\r?\n/);
  const index = lines.findIndex((line) => line.startsWith(`${key}=`));
  if (index === -1) lines.push(`${key}=${value}`);
  else lines[index] = `${key}=${value}`;
  return lines.join("\n");
}

async function uniqueDirectoryName(parent, requested) {
  let name = requested;
  for (let index = 2; await exists(path.join(parent, name)); index += 1) name = `${requested}-${index}`;
  return name;
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
