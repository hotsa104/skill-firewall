import { readFileSync, statSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { join, basename } from "node:path";
import { isMcpFile, flattenMcp } from "./mcp.js";

export interface Source {
  name: string;
  content: string;
}

const SKILL_FILE_RE = /(SKILL\.md|\.mdc?|\.toml)$/i;

/**
 * ファイル内容を読む。.mcp.json は command/args/env/url を平文化した行を末尾に追記し、
 * 既存ルールが「実際に起動されるコマンド」へ当たるようにする（生 JSON も残す）。
 */
function readSkillFile(path: string): string {
  const raw = readFileSync(path, "utf8");
  if (isMcpFile(path)) {
    const flat = flattenMcp(raw);
    if (flat) return `${raw}\n\n${flat}`;
  }
  return raw;
}

/** path（ファイル or ディレクトリ）または URL からスキャン対象テキストを収集する。 */
export async function collect(input: string): Promise<Source[]> {
  if (/^https?:\/\//i.test(input)) {
    const res = await fetch(input, {
      signal: AbortSignal.timeout(15000),
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
    const text = await res.text();
    const MAX = 2 * 1024 * 1024; // 2MB 上限（DoS 対策）
    if (text.length > MAX) {
      throw new Error(`response too large (${text.length} bytes, max ${MAX})`);
    }
    return [{ name: input, content: text }];
  }

  if (!existsSync(input)) {
    throw new Error(`path not found: ${input}`);
  }

  const st = statSync(input);
  if (st.isFile()) {
    return [{ name: input, content: readSkillFile(input) }];
  }

  // ディレクトリ: SKILL.md / .md / .toml を再帰収集
  const sources: Source[] = [];
  walk(input, sources);
  if (sources.length === 0) {
    throw new Error(`no scannable skill files found under: ${input}`);
  }
  return sources;
}

// 歩かないディレクトリ（VCS・依存・ビルド成果物）。
// 注意: .claude / .cursor / .mcp 等の「スキャンしたい設定ディレクトリ」は除外しない。
const SKIP_DIRS = new Set([".git", ".hg", ".svn", "node_modules", "dist", "build", ".next"]);

function walk(dir: string, out: Source[], depth = 0, visited = new Set<string>()): void {
  if (depth > 16) return; // 過大ツリーの暴走防止
  // realpath でループ検出（symlink は辿るが、同じ実体は二度歩かない）。
  // Claude Code のスキルは多くが ~/.agents/skills 等への symlink なので、辿るのは必須。
  let real: string;
  try {
    real = realpathSync(dir);
  } catch {
    return; // dangling symlink 等
  }
  if (visited.has(real)) return;
  visited.add(real);

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    let st;
    try {
      st = statSync(full); // symlink を解決して種別判定
    } catch {
      continue; // dangling symlink
    }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out, depth + 1, visited);
    } else if (st.isFile() && (SKILL_FILE_RE.test(entry.name) || entry.name === ".mcp.json")) {
      out.push({ name: full, content: readSkillFile(full) });
    }
  }
}

export { basename };
