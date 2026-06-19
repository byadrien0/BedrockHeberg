import test from "node:test";
import assert from "node:assert/strict";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { BedrockManager } from "../src/bedrock-manager.js";
import {
  MultiServerManager,
  cleanName,
  normalizeResources,
  performancePreset,
  setProperty,
  slugify,
  validatePort
} from "../src/multi-server-manager.js";

test("slugify creates stable server identifiers", () => {
  assert.equal(slugify("Serveur Créatif #1"), "serveur-creatif-1");
  assert.equal(slugify("  Mon serveur  "), "mon-serveur");
});

test("cleanName trims and limits server names", () => {
  assert.equal(cleanName("  Principal  "), "Principal");
  assert.equal(cleanName(""), "Serveur");
  assert.equal(cleanName("x".repeat(100)).length, 80);
});

test("validatePort accepts Bedrock ports and rejects invalid values", () => {
  assert.doesNotThrow(() => validatePort(19132));
  assert.throws(() => validatePort(0), /Port invalide/);
  assert.throws(() => validatePort(65535), /Port invalide/);
  assert.throws(() => validatePort(19132.5), /Port invalide/);
});

test("setProperty updates existing values and adds missing values", () => {
  assert.equal(setProperty("server-port=19132\nmax-players=10", "server-port", "19140"), "server-port=19140\nmax-players=10");
  assert.equal(setProperty("server-port=19132", "level-name", "Monde"), "server-port=19132\nlevel-name=Monde");
});

test("normalizeResources clamps metadata to supported bounds", () => {
  assert.deepEqual(normalizeResources({ performanceProfile:"custom", ramMb:1, cpuCores:100, storageGb:"bad", viewDistance:200, tickDistance:1 }), {
    performanceProfile: "custom",
    ramMb: 256,
    cpuCores: 64,
    storageGb: 10,
    viewDistance: 96,
    tickDistance: 4
  });
});

test("performance profiles provide coherent Bedrock limits", () => {
  assert.deepEqual(normalizeResources({ performanceProfile:"performance", ramMb:512 }), performancePreset("performance"));
  assert.equal(performancePreset("balanced").cpuCores, 2);
  assert.equal(performancePreset("balanced").ramMb, 2048);
});

test("server registry writes replace an existing JSON file cleanly", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-panel-test-"));
  try {
    const manager = new MultiServerManager({ rootDir, autoStart: false });
    await manager.initialize();
    assert.equal(await manager.requireManager("principal").readProperty("server-port"), "19132");
    await manager.update("principal", { resources:{ performanceProfile:"performance" } });
    assert.equal(await manager.requireManager("principal").readProperty("max-threads"), "4");
    assert.equal(await manager.requireManager("principal").readProperty("view-distance"), "32");
    manager.servers[0].name = "Serveur test";
    await manager.saveConfig();

    const saved = JSON.parse(await fsp.readFile(manager.configPath, "utf8"));
    assert.equal(saved.servers[0].name, "Serveur test");
    assert.equal(await fsp.stat(manager.configPath).then(() => true), true);
  } finally {
    await fsp.rm(rootDir, { recursive: true, force: true });
  }
});

test("missing server.properties is treated as an empty configuration", async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-properties-test-"));
  try {
    const manager = new BedrockManager({
      rootDir,
      serverDir: path.join(rootDir, "server"),
      backupDir: path.join(rootDir, "backups"),
      seedDir: path.join(rootDir, "missing-seed")
    });
    assert.equal(await manager.readProperties(), "");
  } finally {
    await fsp.rm(rootDir, { recursive: true, force: true });
  }
});

test("Windows can create server configuration before the executable is installed", { skip: process.platform !== "win32" }, async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "bedrock-create-test-"));
  try {
    const manager = new MultiServerManager({ rootDir, autoStart: false });
    await manager.initialize();
    const created = await manager.create({ name: "Serveur local", port: 19140 });
    const properties = await fsp.readFile(path.join(created.serverDir, "server.properties"), "utf8");
    assert.match(properties, /server-name=Serveur local/);
    assert.match(properties, /server-port=19140/);
  } finally {
    await fsp.rm(rootDir, { recursive: true, force: true });
  }
});
