import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { BedrockManager } from "./bedrock-manager.js";

const DEFAULT_ID = "principal";

export class MultiServerManager {
  constructor(options) {
    this.rootDir = options.rootDir;
    this.autoStart = options.autoStart;
    this.downloadUrl = options.downloadUrl || "";
    this.seedDir = path.resolve(options.seedDir || defaultSeedDir(options.rootDir));
    this.legacyServerDir = path.resolve(options.serverDir || defaultLegacyServerDir(options.rootDir));
    this.instancesRoot = path.resolve(options.instancesRoot || defaultInstancesRoot(options.rootDir));
    this.backupRoot = path.resolve(options.backupRoot || defaultBackupRoot(options.rootDir));
    this.configDir = path.resolve(options.configDir || defaultConfigDir(options.rootDir));
    this.configPath = path.join(this.configDir, "servers.json");
    this.servers = [];
    this.managers = new Map();
  }

  async initialize() {
    await fsp.mkdir(this.configDir, { recursive: true });
    await fsp.mkdir(this.instancesRoot, { recursive: true });
    await fsp.mkdir(this.backupRoot, { recursive: true });
    await this.loadConfig();
    if (this.servers.length === 0) {
      this.servers.push({
        id: DEFAULT_ID,
        name: "Serveur principal",
        serverDir: this.legacyServerDir,
        backupDir: process.env.BACKUP_DIR ? path.resolve(process.env.BACKUP_DIR) : path.join(this.backupRoot, DEFAULT_ID),
        seedDir: this.seedDir,
        autoStart: this.autoStart,
        resources: defaultResources(),
        createdAt: new Date().toISOString()
      });
      await this.saveConfig();
    }
    this.rebuildManagers();
  }

  async list() {
    const rows = [];
    for (const server of this.servers) {
      const manager = this.requireManager(server.id);
      rows.push({
        ...publicServer(server),
        status: await manager.status().catch((error) => ({
          running: false,
          uptimeSeconds: 0,
          gamePort: "",
          hostIps: [],
          worldName: "",
          backupCount: 0,
          serverDir: server.serverDir,
          backupDir: server.backupDir,
          error: error.message
        }))
      });
    }
    return rows;
  }

  get(id) {
    const server = this.servers.find((item) => item.id === id);
    if (!server) return null;
    return { meta: server, manager: this.requireManager(id) };
  }

  require(id) {
    const found = this.get(id);
    if (!found) throw new Error("Serveur introuvable.");
    return found;
  }

  requireManager(id) {
    const manager = this.managers.get(id);
    if (!manager) throw new Error("Serveur introuvable.");
    return manager;
  }

  async create(input) {
    const name = cleanName(input.name || "Nouveau serveur");
    const id = await this.nextId(name);
    const port = Number(input.port || (await this.nextPort()));
    validatePort(port);
    await this.assertPortAvailable(port);
    const serverDir = path.join(this.instancesRoot, id);
    const backupDir = path.join(this.backupRoot, id);
    const template = input.templateServerId ? this.get(input.templateServerId) : null;
    const seedDir = template ? template.meta.serverDir : this.seedDir;
    const server = {
      id,
      name,
      serverDir,
      backupDir,
      seedDir,
      autoStart: Boolean(input.autoStart),
      resources: defaultResources(),
      createdAt: new Date().toISOString()
    };
    this.servers.push(server);
    this.rebuildManagers();
    const manager = this.requireManager(id);
    try {
      await manager.prepare({ allowMissingExecutable: process.platform === "win32" });
      await updateProperties(manager, { name, port });
      await this.saveConfig();
      return { ...publicServer(server), status: await manager.status() };
    } catch (error) {
      this.servers = this.servers.filter((item) => item.id !== id);
      this.managers.delete(id);
      await fsp.rm(serverDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(backupDir, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  }

  async update(id, input) {
    const { meta, manager } = this.require(id);
    if (typeof input.name === "string" && input.name.trim()) {
      meta.name = cleanName(input.name);
    }
    if (typeof input.autoStart === "boolean") {
      meta.autoStart = input.autoStart;
      manager.autoStart = input.autoStart;
    }
    if (input.resources) {
      meta.resources = normalizeResources(input.resources);
    }
    if (input.port !== undefined && input.port !== "") {
      const port = Number(input.port);
      validatePort(port);
      await this.assertPortAvailable(port, id);
      await updateProperties(manager, { name: meta.name, port });
    } else if (input.name) {
      await updateProperties(manager, { name: meta.name });
    }
    await this.saveConfig();
    return { ...publicServer(meta), status: await manager.status() };
  }

  async delete(id) {
    const index = this.servers.findIndex((server) => server.id === id);
    if (index === -1) throw new Error("Serveur introuvable.");
    const [server] = this.servers.splice(index, 1);
    const manager = this.requireManager(id);
    await manager.stop();
    this.managers.delete(id);
    if (isInside(this.instancesRoot, server.serverDir)) {
      await fsp.rm(server.serverDir, { recursive: true, force: true });
    }
    if (isInside(this.backupRoot, server.backupDir)) {
      await fsp.rm(server.backupDir, { recursive: true, force: true });
    }
    await this.saveConfig();
  }

  async startAutoServers() {
    for (const server of this.servers) {
      if (!server.autoStart) continue;
      this.requireManager(server.id).start().catch((error) => {
        console.error(`Demarrage ${server.name} impossible: ${error.message}`);
      });
    }
  }

  async loadConfig() {
    try {
      const data = JSON.parse(await fsp.readFile(this.configPath, "utf8"));
      this.servers = Array.isArray(data.servers) ? data.servers.map(normalizeServer) : [];
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.servers = [];
    }
  }

  async saveConfig() {
    const data = {
      version: 1,
      servers: this.servers.map(normalizeServer)
    };
    const temporaryPath = `${this.configPath}.${process.pid}.tmp`;
    await fsp.writeFile(temporaryPath, JSON.stringify(data, null, 2), "utf8");
    try {
      await fsp.rename(temporaryPath, this.configPath);
    } finally {
      await fsp.rm(temporaryPath, { force: true }).catch(() => {});
    }
  }

  rebuildManagers() {
    const next = new Map();
    for (const server of this.servers) {
      const previous = this.managers.get(server.id);
      if (previous) {
        previous.autoStart = server.autoStart;
        next.set(server.id, previous);
        continue;
      }
      next.set(server.id, new BedrockManager({
        rootDir: this.rootDir,
        serverDir: server.serverDir,
        seedDir: server.seedDir || this.seedDir,
        backupDir: server.backupDir,
        downloadUrl: this.downloadUrl,
        autoStart: server.autoStart
      }));
    }
    this.managers = next;
  }

  async nextId(name) {
    const base = slugify(name) || "serveur";
    const used = new Set(this.servers.map((server) => server.id));
    if (!used.has(base)) return base;
    for (let index = 2; index < 1000; index += 1) {
      const id = `${base}-${index}`;
      if (!used.has(id)) return id;
    }
    return `${base}-${crypto.randomBytes(3).toString("hex")}`;
  }

  async nextPort() {
    const ports = [];
    for (const server of this.servers) {
      const port = Number(await this.requireManager(server.id).readProperty("server-port").catch(() => ""));
      if (Number.isInteger(port)) ports.push(port);
    }
    let port = 19132;
    while (ports.includes(port)) port += 2;
    return port;
  }

  async assertPortAvailable(port, ignoredId = "") {
    for (const server of this.servers) {
      if (server.id === ignoredId) continue;
      const current = Number(await this.requireManager(server.id).readProperty("server-port").catch(() => ""));
      if (current === port) {
        throw new Error(`Le port ${port} est deja utilise par ${server.name}.`);
      }
      if (current === port + 1) {
        throw new Error(`Le port IPv6 associe ${port + 1} est deja utilise par ${server.name}.`);
      }
    }
  }
}

async function updateProperties(manager, patch) {
  let content = await manager.readProperties();
  if (!content.trim()) {
    content = [
      "server-name=Dedicated Server",
      "gamemode=survival",
      "difficulty=easy",
      "allow-cheats=false",
      "max-players=10",
      "online-mode=true",
      "allow-list=false",
      "server-port=19132",
      "server-portv6=19133",
      "enable-lan-visibility=false",
      "level-name=Bedrock level",
      ""
    ].join("\n");
  }
  if (patch.name) content = setProperty(content, "server-name", patch.name);
  if (patch.port) {
    content = setProperty(content, "server-port", String(patch.port));
    content = setProperty(content, "server-portv6", String(patch.port + 1));
    content = setProperty(content, "enable-lan-visibility", "false");
  }
  await manager.writeProperties(content);
}

function setProperty(content, key, value) {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex((line) => line.startsWith(`${key}=`));
  if (index >= 0) {
    lines[index] = `${key}=${value}`;
  } else {
    lines.push(`${key}=${value}`);
  }
  return lines.join("\n");
}

function normalizeServer(server) {
  return {
    id: String(server.id || DEFAULT_ID),
    name: cleanName(server.name || "Serveur"),
    serverDir: path.resolve(server.serverDir),
    backupDir: path.resolve(server.backupDir),
    seedDir: server.seedDir ? path.resolve(server.seedDir) : undefined,
    autoStart: Boolean(server.autoStart),
    resources: normalizeResources(server.resources || {}),
    createdAt: server.createdAt || new Date().toISOString()
  };
}

function publicServer(server) {
  return {
    id: server.id,
    name: server.name,
    serverDir: server.serverDir,
    backupDir: server.backupDir,
    autoStart: server.autoStart,
    resources: normalizeResources(server.resources || {}),
    createdAt: server.createdAt,
    protected: false
  };
}

function defaultResources() {
  return { ramMb: 2048, cpuCores: 1, storageGb: 5 };
}

function normalizeResources(resources) {
  const defaults = defaultResources();
  return {
    ramMb: clampInt(resources.ramMb, 256, 131072, defaults.ramMb),
    cpuCores: clampNumber(resources.cpuCores, 0.25, 64, defaults.cpuCores),
    storageGb: clampInt(resources.storageGb, 1, 4096, defaults.storageGb)
  };
}

function clampInt(value, min, max, fallback) {
  const number = Number.parseInt(value, 10);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

function clampNumber(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

function cleanName(value) {
  return String(value).trim().slice(0, 80) || "Serveur";
}

function slugify(value) {
  return String(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65534) {
    throw new Error("Port invalide.");
  }
}

function defaultLegacyServerDir(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/servers/principal";
  }
  return path.join(rootDir, "servers", "principal");
}

function defaultInstancesRoot(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/servers";
  }
  return path.join(rootDir, "servers");
}

function defaultBackupRoot(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/backups";
  }
  return path.join(rootDir, "backups");
}

function defaultConfigDir(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/data/panel";
  }
  return path.join(rootDir, ".panel");
}

function defaultSeedDir(rootDir) {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID) {
    return "/opt/bedrock-seed";
  }
  return path.join(rootDir, "seed");
}

export { cleanName, normalizeResources, setProperty, slugify, validatePort };

function isInside(parent, child) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative);
}
