import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

export class ActivityStore {
  constructor(file, limit = 500) {
    this.file = path.resolve(file);
    this.limit = limit;
    this.entries = [];
    this.writeQueue = Promise.resolve();
  }

  async initialize() {
    await fsp.mkdir(path.dirname(this.file), { recursive: true });
    try {
      const data = JSON.parse(await fsp.readFile(this.file, "utf8"));
      this.entries = Array.isArray(data.entries) ? data.entries.slice(-this.limit) : [];
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }

  async add(entry) {
    const row = {
      id: crypto.randomBytes(8).toString("hex"),
      serverId: String(entry.serverId || ""),
      user: String(entry.user || "system"),
      action: String(entry.action || "unknown"),
      status: entry.status === "error" ? "error" : "success",
      message: String(entry.message || ""),
      createdAt: new Date().toISOString()
    };
    this.entries.push(row);
    if (this.entries.length > this.limit) this.entries.splice(0, this.entries.length - this.limit);
    this.writeQueue = this.writeQueue.catch(() => {}).then(() => this.save());
    await this.writeQueue;
    return row;
  }

  list(serverId = "", limit = 100) {
    const rows = serverId ? this.entries.filter((entry) => entry.serverId === serverId) : this.entries;
    return rows.slice(-Math.max(1, Math.min(500, Number(limit) || 100))).reverse();
  }

  async save() {
    const temporary = `${this.file}.${process.pid}.tmp`;
    await fsp.writeFile(temporary, JSON.stringify({ version: 1, entries: this.entries }, null, 2), "utf8");
    try {
      await fsp.rename(temporary, this.file);
    } finally {
      await fsp.rm(temporary, { force: true }).catch(() => {});
    }
  }
}
