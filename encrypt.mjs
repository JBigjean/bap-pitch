// Re-encrypts the one-pager into index.html.
// Usage: node encrypt.mjs <path to one-pager .html>
// Asks for the password (hidden) and checks it opens the current page first,
// so the password stays the same for people who already have it.
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import readline from "node:readline";

const src = process.argv[2];
if (!src) { console.error("Usage: node encrypt.mjs <one-pager.html>"); process.exit(1); }

const indexPath = new URL("./index.html", import.meta.url);
const index = readFileSync(indexPath, "utf8");
const line = /^const P = (\{.*\});$/m;
const current = JSON.parse(index.match(line)[1]);

const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const toB64 = (u) => Buffer.from(u).toString("base64");

async function keyFor(pw, salt, iter, usage) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, [usage]);
}

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
    rl.question(question, (a) => { rl.close(); process.stdout.write("\n"); resolve(a); });
  });
}

const pw = await askHidden("Password of the current page: ");
try {
  const key = await keyFor(pw, b64(current.salt), current.iter, "decrypt");
  await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(current.iv) }, key, b64(current.ct));
} catch {
  console.error("That password doesn't open the current page. Nothing changed.");
  process.exit(1);
}

let body = readFileSync(src, "utf8");
if (!/^\s*<!doctype/i.test(body)) {
  body = `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<meta name="robots" content="noindex">\n</head>\n<body style="margin:0">\n${body}\n</body>\n</html>\n`;
}

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const iter = current.iter;
const key = await keyFor(pw, salt, iter, "encrypt");
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(body)));
const P = { v: 1, iter, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) };
writeFileSync(indexPath, index.replace(line, () => `const P = ${JSON.stringify(P)};`));
console.log("index.html updated with the new one-pager. Same password.");
