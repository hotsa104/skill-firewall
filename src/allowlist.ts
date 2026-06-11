import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";

export interface AllowEntry {
  hash: string;
  id: string;
  approvedAt: string;
}

interface AllowFile {
  version: 1;
  entries: AllowEntry[];
}

const CONFIG_DIR = join(homedir(), ".config", "skill-firewall");
const ALLOWLIST_PATH = join(CONFIG_DIR, "allowlist.json");

/** スキル内容の sha256。承認済み判定のキー。 */
export function hashContent(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export function allowlistPath(): string {
  return ALLOWLIST_PATH;
}

function load(): AllowFile {
  if (!existsSync(ALLOWLIST_PATH)) return { version: 1, entries: [] };
  try {
    const parsed = JSON.parse(readFileSync(ALLOWLIST_PATH, "utf8")) as AllowFile;
    if (!Array.isArray(parsed.entries)) return { version: 1, entries: [] };
    return parsed;
  } catch {
    return { version: 1, entries: [] };
  }
}

function save(data: AllowFile): void {
  mkdirSync(dirname(ALLOWLIST_PATH), { recursive: true });
  writeFileSync(ALLOWLIST_PATH, JSON.stringify(data, null, 2) + "\n", "utf8");
}

export function isAllowed(content: string): boolean {
  const h = hashContent(content);
  return load().entries.some((e) => e.hash === h);
}

/** スキルを承認リストに追加（同一ハッシュは重複登録しない）。approvedAt は呼び出し側が渡す。 */
export function allow(content: string, id: string, approvedAt: string): AllowEntry {
  const data = load();
  const hash = hashContent(content);
  const existing = data.entries.find((e) => e.hash === hash);
  if (existing) return existing;
  const entry: AllowEntry = { hash, id, approvedAt };
  data.entries.push(entry);
  save(data);
  return entry;
}

export function listAllowed(): AllowEntry[] {
  return load().entries;
}
