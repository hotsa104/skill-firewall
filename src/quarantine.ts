import {
  mkdirSync,
  renameSync,
  existsSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  cpSync,
  rmSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, basename } from "node:path";

const QUARANTINE_DIR = join(homedir(), ".claude", "skills-quarantine");

export interface QuarantineRecord {
  id: string;
  from: string;
  to: string;
  reason: string;
  at: string;
}

export function quarantineDir(): string {
  return QUARANTINE_DIR;
}

/**
 * スキル（フォルダ or ファイル）を隔離ディレクトリへ退避する。
 * 元の場所からは取り除かれ、エージェントが読めなくなる。
 * stamp はタイムスタンプ等の一意サフィックス（呼び出し側が渡す＝テスト容易性）。
 */
export function quarantine(root: string, id: string, reason: string, stamp: string): QuarantineRecord {
  const dest = join(QUARANTINE_DIR, `${id}-${stamp}`);
  mkdirSync(QUARANTINE_DIR, { recursive: true });

  // rename はクロスデバイスで失敗しうるので cp+rm にフォールバック
  try {
    renameSync(root, dest);
  } catch {
    cpSync(root, dest, { recursive: true });
    rmSync(root, { recursive: true, force: true });
  }

  const record: QuarantineRecord = { id, from: root, to: dest, reason, at: stamp };
  // 隔離理由を同梱（復元判断の材料）
  const metaPath = statSync(dest).isDirectory()
    ? join(dest, ".quarantine-reason.txt")
    : `${dest}.quarantine-reason.txt`;
  writeFileSync(metaPath, `${reason}\nquarantined-from: ${root}\nat: ${stamp}\n`, "utf8");
  return record;
}

export interface QuarantineEntry {
  name: string;
  path: string;
  reason?: string;
  /** quarantined = 自動隔離された危険スキル / staged = add で配置保留中 */
  kind: "quarantined" | "staged";
}

/** 隔離ディレクトリの中身を一覧する（ユーザーが「何が隔離されたか」を確認するための UX）。 */
export function listQuarantined(): QuarantineEntry[] {
  const entries: QuarantineEntry[] = [];
  if (!existsSync(QUARANTINE_DIR)) return entries;

  for (const name of readdirSync(QUARANTINE_DIR)) {
    if (name === "staging") continue;
    if (name.endsWith(".quarantine-reason.txt")) continue; // 単独ファイルの理由メモ自体は除外
    const path = join(QUARANTINE_DIR, name);
    entries.push({ name, path, reason: readReason(path), kind: "quarantined" });
  }

  const staging = join(QUARANTINE_DIR, "staging");
  if (existsSync(staging)) {
    for (const name of readdirSync(staging)) {
      entries.push({ name, path: join(staging, name), kind: "staged" });
    }
  }
  return entries;
}

function readReason(entryPath: string): string | undefined {
  try {
    const meta = statSync(entryPath).isDirectory()
      ? join(entryPath, ".quarantine-reason.txt")
      : `${entryPath}.quarantine-reason.txt`;
    if (existsSync(meta)) return readFileSync(meta, "utf8").split("\n")[0].trim();
  } catch {
    /* noop */
  }
  return undefined;
}

export { existsSync, basename, QUARANTINE_DIR };
