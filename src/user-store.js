import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

export class UserStore {
  constructor(file) {
    this.file = path.resolve(file);
    this.users = [];
  }

  async initialize(initialPassword) {
    await fsp.mkdir(path.dirname(this.file), { recursive: true });
    try {
      const data = JSON.parse(await fsp.readFile(this.file, "utf8"));
      this.users = Array.isArray(data.users) ? data.users : [];
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (!this.users.length) {
      this.users.push({ username: "admin", role: "admin", passwordHash: hashPassword(initialPassword), totpSecret: "", totpEnabled: false });
      await this.save();
    }
  }

  async authenticate(username, password, token = "") {
    const user = this.users.find((item) => item.username.toLowerCase() === String(username || "admin").trim().toLowerCase());
    if (!user || !verifyPassword(password, user.passwordHash)) return null;
    if (user.totpEnabled && !verifyTotp(user.totpSecret, token)) return { requiresTotp: true };
    return { username: user.username, role: user.role, totpEnabled: user.totpEnabled };
  }

  list() {
    return this.users.map(({ username, role, totpEnabled }) => ({ username, role, totpEnabled }));
  }

  async create(input) {
    const username = cleanUsername(input.username);
    if (this.users.some((user) => user.username.toLowerCase() === username.toLowerCase())) throw new Error("Cet utilisateur existe déjà.");
    if (String(input.password || "").length < 10) throw new Error("Le mot de passe doit contenir au moins 10 caractères.");
    const user = { username, role: input.role === "viewer" ? "viewer" : "admin", passwordHash: hashPassword(input.password), totpSecret: "", totpEnabled: false };
    this.users.push(user);
    await this.save();
    return { username: user.username, role: user.role, totpEnabled: false };
  }

  async remove(username, currentUsername) {
    if (username === currentUsername) throw new Error("Tu ne peux pas supprimer ton propre compte.");
    const user = this.users.find((item) => item.username === username);
    if (!user) throw new Error("Utilisateur introuvable.");
    if (user.role === "admin" && this.users.filter((item) => item.role === "admin").length === 1) throw new Error("Le dernier administrateur ne peut pas être supprimé.");
    this.users = this.users.filter((item) => item.username !== username);
    await this.save();
  }

  async beginTotp(username) {
    const user = this.require(username);
    user.totpSecret = base32Encode(crypto.randomBytes(20));
    user.totpEnabled = false;
    await this.save();
    return {
      secret: user.totpSecret,
      uri: `otpauth://totp/BedrockHeberg:${encodeURIComponent(username)}?secret=${user.totpSecret}&issuer=BedrockHeberg&digits=6&period=30`
    };
  }

  async enableTotp(username, token) {
    const user = this.require(username);
    if (!user.totpSecret || !verifyTotp(user.totpSecret, token)) throw new Error("Code TOTP invalide.");
    user.totpEnabled = true;
    await this.save();
  }

  async disableTotp(username) {
    const user = this.require(username);
    user.totpSecret = "";
    user.totpEnabled = false;
    await this.save();
  }

  require(username) {
    const user = this.users.find((item) => item.username === username);
    if (!user) throw new Error("Utilisateur introuvable.");
    return user;
  }

  async save() {
    const temporary = `${this.file}.${process.pid}.tmp`;
    await fsp.writeFile(temporary, JSON.stringify({ version: 1, users: this.users }, null, 2), "utf8");
    try {
      await fsp.rename(temporary, this.file);
    } finally {
      await fsp.rm(temporary, { force: true }).catch(() => {});
    }
  }
}

function cleanUsername(value) {
  const username = String(value || "").trim();
  if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) throw new Error("Nom utilisateur invalide.");
  return username;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return `scrypt:${salt.toString("hex")}:${hash.toString("hex")}`;
}

function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = String(stored || "").split(":");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(String(password), Buffer.from(saltHex, "hex"), expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function verifyTotp(secret, token, now = Date.now()) {
  const value = String(token || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(value)) return false;
  const counter = Math.floor(now / 30000);
  return [-1, 0, 1].some((offset) => totp(secret, counter + offset) === value);
}

function totp(secret, counter) {
  const key = base32Decode(secret);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, "0");
}

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");
  return bits.match(/.{1,5}/g).map((chunk) => alphabet[Number.parseInt(chunk.padEnd(5, "0"), 2)]).join("");
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = String(value).toUpperCase().replace(/=+$/, "").split("").map((char) => alphabet.indexOf(char).toString(2).padStart(5, "0")).join("");
  return Buffer.from((bits.match(/.{8}/g) || []).map((byte) => Number.parseInt(byte, 2)));
}

export { hashPassword, totp, verifyPassword, verifyTotp };
