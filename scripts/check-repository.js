import fs from "node:fs";

const trackedFiles = fs.readFileSync(0, "utf8")
  .split("\0")
  .filter(Boolean);

const forbidden = [
  /(^|\/)(servers?|worlds?|backups?|config|data|\.panel)(\/|$)/i,
  /(^|\/)bedrock_server(?:\.exe)?$/i,
  /(^|\/)(server\.properties|allowlist\.json|permissions\.json)$/i,
  /(^|\/)(runtime-secrets|users|activity)\.json$/i,
  /(^|\/)sessions(\/|$)/i,
  /\.(?:log|zip|mcworld|mcpack|mcaddon)$/i,
  /(^|\/)\.env(?:\.|$)/i
];

const allowed = new Set([".env.example"]);
const unsafe = trackedFiles.filter((file) => !allowed.has(file) && forbidden.some((pattern) => pattern.test(file)));

if (unsafe.length) {
  console.error("Fichiers locaux interdits dans le depot :");
  unsafe.forEach((file) => console.error(`- ${file}`));
  process.exit(1);
}

console.log(`${trackedFiles.length} fichiers suivis verifies : aucune donnee serveur locale.`);
