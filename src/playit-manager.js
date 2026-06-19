import { spawn } from "node:child_process";

export class PlayitManager {
  constructor(options = {}) {
    this.secret = String(options.secret || "").trim();
    this.address = String(options.address || "").trim();
    this.binary = options.binary || (process.platform === "win32" ? "playit.exe" : "playit");
    this.arguments = options.arguments || ["-s", "--secret", this.secret, "--platform_docker", "start"];
    this.spawn = options.spawn || spawn;
    this.child = null;
    this.retryTimer = null;
    this.stopping = false;
    this.state = this.secret ? "stopped" : "disabled";
    this.lastError = "";
    this.logs = [];
    this.lastTunnelLogAt = 0;
  }

  start() {
    if (!this.secret || this.child || this.stopping) return;
    this.state = "starting";
    this.lastError = "";
    const child = this.spawn(this.binary, this.arguments, {
      env:{ ...process.env, SECRET_KEY:this.secret },
      stdio:["ignore", "pipe", "pipe"],
      windowsHide:true
    });
    this.child = child;
    child.once("spawn", () => {
      this.state = "running";
      this.appendLog("Agent Playit demarre.");
    });
    child.stdout.on("data", (chunk) => this.appendLog(chunk.toString()));
    child.stderr.on("data", (chunk) => this.appendLog(chunk.toString()));
    child.on("error", (error) => {
      this.lastError = error.message;
      this.state = "error";
      this.appendLog(`Erreur Playit: ${error.message}`);
    });
    child.on("exit", (code, signal) => {
      this.child = null;
      if (this.stopping) {
        this.state = "stopped";
        return;
      }
      this.state = "error";
      this.lastError = `Agent arrete (code ${code ?? "inconnu"}, signal ${signal ?? "aucun"}).`;
      this.appendLog(this.lastError);
      this.retryTimer = setTimeout(() => this.start(), 10000);
      this.retryTimer.unref?.();
    });
  }

  stop() {
    this.stopping = true;
    clearTimeout(this.retryTimer);
    this.child?.kill("SIGTERM");
  }

  status() {
    return {
      enabled:Boolean(this.secret),
      running:this.state === "running",
      state:this.state,
      address:this.address,
      lastError:this.lastError
    };
  }

  appendLog(value) {
    const raw = String(value || "");
    const safe = (this.secret ? raw.replaceAll(this.secret, "[secret]") : raw).trim();
    if (!safe) return;
    if (/tunnel running, \d+ tunnels? registered/i.test(safe)) {
      const now = Date.now();
      if (now - this.lastTunnelLogAt < 60000) return;
      this.lastTunnelLogAt = now;
    }
    this.logs.push(safe);
    if (this.logs.length > 100) this.logs.splice(0, this.logs.length - 100);
    console.log(`[playit] ${safe}`);
  }
}
