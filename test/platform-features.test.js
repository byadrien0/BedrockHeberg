import test from "node:test";
import assert from "node:assert/strict";
import fsp from "node:fs/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import archiver from "archiver";
import { ActivityStore } from "../src/activity-store.js";
import { BedrockManager, bedrockDownloadUrlFromHtml, bedrockDownloadUrlFromManifest } from "../src/bedrock-manager.js";
import { normalizeBackupPolicy } from "../src/multi-server-manager.js";
import { UserStore, totp } from "../src/user-store.js";

test("official Bedrock links select the current operating system", () => {
  const manifest = { result:{ links:[
    { downloadType:"serverBedrockWindows", downloadUrl:"https://example.test/bin-win/bedrock.zip" },
    { downloadType:"serverBedrockLinux", downloadUrl:"https://example.test/bin-linux/bedrock.zip" }
  ] } };
  assert.match(bedrockDownloadUrlFromManifest(manifest, "serverBedrockWindows"), /bin-win/);
  assert.match(bedrockDownloadUrlFromManifest(manifest, "serverBedrockLinux"), /bin-linux/);

  const html = [
    "https:\\/\\/www.minecraft.net\\/bedrockdedicatedserver\\/bin-win\\/bedrock-server-1.21.0.1.zip",
    "https://www.minecraft.net/bedrockdedicatedserver/bin-linux/bedrock-server-1.21.0.1.zip"
  ].join(" ");
  assert.match(bedrockDownloadUrlFromHtml(html, "win32"), /bin-win/);
  assert.match(bedrockDownloadUrlFromHtml(html, "linux"), /bin-linux/);
});

test("operation queue reports progress and rejects duplicate queued work", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-operation-test-"));
  try {
    const manager = new BedrockManager({ rootDir, serverDir:path.join(rootDir, "server"), backupDir:path.join(rootDir, "backups") });
    const events = [];
    manager.subscribe((event) => events.push(event));
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const first = manager.runOperation("backing-up", async (progress) => { progress(40); await gate; return "ok"; });
    await assert.rejects(() => manager.runOperation("backing-up", async () => {}), /déjà en cours/);
    release();
    assert.equal(await first, "ok");
    assert.equal(manager.operation.type, "idle");
    assert.ok(events.some((event) => event.data?.operation?.progress === 40));
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("server lifecycle distinguishes created, installed and operational", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-lifecycle-test-"));
  try {
    const manager = new BedrockManager({ rootDir, serverDir:path.join(rootDir, "server"), backupDir:path.join(rootDir, "backups") });
    await manager.writeProperties("server-port=19132\n");
    assert.equal((await manager.status()).lifecycle, "created");
    await fsp.writeFile(manager.executablePath(), "placeholder");
    assert.equal((await manager.status()).lifecycle, "installed");
    manager.persistentState.firstStartedAt = new Date().toISOString();
    await manager.savePersistentState();
    assert.equal((await manager.status()).lifecycle, "operational");
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("backup policy is normalized to safe scheduler limits", () => {
  assert.deepEqual(normalizeBackupPolicy({ enabled:true, intervalMinutes:1, retention:200 }), { enabled:true, intervalMinutes:15, retention:100 });
});

test("activity history persists and filters by server", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-activity-test-"));
  try {
    const file = path.join(rootDir, "activity.json");
    const store = new ActivityStore(file);
    await store.initialize();
    await store.add({ serverId:"one", action:"server.start", message:"ok" });
    await store.add({ serverId:"two", action:"server.stop", status:"error", message:"fail" });
    const reloaded = new ActivityStore(file);
    await reloaded.initialize();
    assert.equal(reloaded.list("one").length, 1);
    assert.equal(reloaded.list("two")[0].status, "error");
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("user store supports roles and optional TOTP", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-user-test-"));
  try {
    const store = new UserStore(path.join(rootDir, "users.json"));
    await store.initialize("initial-password");
    await store.create({ username:"observer", password:"observer-password", role:"viewer" });
    assert.equal((await store.authenticate("observer", "observer-password")).role, "viewer");
    const setup = await store.beginTotp("admin");
    const token = totp(setup.secret, Math.floor(Date.now() / 30000));
    await store.enableTotp("admin", token);
    assert.equal((await store.authenticate("admin", "initial-password", token)).totpEnabled, true);
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("bootstrap can repair a sole inaccessible admin account", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-bootstrap-test-"));
  try {
    const file = path.join(rootDir, "users.json");
    const first = new UserStore(file);
    await first.initialize("lost-password");
    const restarted = new UserStore(file);
    await restarted.initialize("persistent-password", { resetSoleAdminPassword:true });
    assert.equal((await restarted.authenticate("admin", "persistent-password")).role, "admin");
    assert.equal(await restarted.authenticate("admin", "lost-password"), null);
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("file operations and backups preserve server data", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-files-test-"));
  try {
    const manager = new BedrockManager({ rootDir, serverDir:path.join(rootDir, "server"), backupDir:path.join(rootDir, "backups") });
    await manager.writeProperties("server-port=19132\nlevel-name=Bedrock level\n");
    await manager.writeFile("notes.txt", "hello");
    const renamed = await manager.renameFile("notes.txt", "renamed.txt");
    assert.equal(await manager.readFile(renamed.path), "hello");
    const backup = await manager.createBackup("manual");
    assert.equal(backup.origin, "manual");
    assert.equal((await manager.listBackups()).length, 1);
    await manager.deleteBackup(backup.name);
    assert.equal((await manager.listBackups()).length, 0);
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

test("mcworld archives can be imported and listed", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-world-test-"));
  try {
    const source = path.join(rootDir, "source");
    await fsp.mkdir(source, { recursive:true });
    await fsp.writeFile(path.join(source, "levelname.txt"), "Mon monde", "utf8");
    await fsp.writeFile(path.join(source, "level.dat"), "test", "utf8");
    const archive = path.join(rootDir, "world.mcworld");
    await createArchive(source, archive);
    const manager = new BedrockManager({ rootDir, serverDir:path.join(rootDir, "server"), backupDir:path.join(rootDir, "backups") });
    await manager.writeProperties("level-name=Mon monde\n");
    const imported = await manager.importWorld(archive, "world.mcworld");
    assert.equal(imported.name, "Mon monde");
    assert.equal((await manager.listWorlds())[0].active, true);
  } finally {
    await fsp.rm(rootDir, { recursive:true, force:true });
  }
});

function createArchive(source, target) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(target);
    const archive = archiver("zip", { zlib:{ level:1 } });
    output.on("close", resolve);
    archive.on("error", reject);
    archive.pipe(output);
    archive.directory(source, false);
    archive.finalize();
  });
}
