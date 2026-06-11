import { spawnSync } from "node:child_process";
import {
  existsSync,
  statSync,
  mkdirSync,
  writeFileSync,
  cpSync,
  renameSync,
  rmSync,
} from "node:fs";
import { join, basename, dirname } from "node:path";
import { loadRules, scanText, worstSeverity, type ScanResult, type Severity, type Finding } from "./scanner.js";
import { collect } from "./collect.js";
import { judge, llmAvailable, type LlmVerdict } from "./llm.js";
import { checkProvenance, type Provenance } from "./provenance.js";
import { parseGitHub } from "./provenance.js";
import { quarantineDir } from "./quarantine.js";
import { defaultInstallDir } from "./skilldirs.js";

/**
 * 検疫付きインストーラ（F-2）。
 *
 * スキルを skills ディレクトリへ即配置せず、まず検疫(staging)へ取得 → 静的+LLM+出所スキャン →
 * 安全/承認時のみ本来の場所へ配置する。危険・要確認なら検疫に留めてレポートする。
 *
 * 対応取得元:
 *  - ローカルパス（ファイル / ディレクトリ）
 *  - 単体 URL（http(s) の SKILL.md 等。raw.githubusercontent / github blob を含む）
 *  - GitHub リポジトリ（github.com/owner/repo, github:owner/repo[#ref], *.git）→ git clone
 *
 * npm パッケージのインストールは現状スコープ外（provenance は npm: で確認可能）。
 */

export interface AddOptions {
  cwd: string;
  /** 配置先 skills ディレクトリ（既定: プロジェクト .claude/skills か ~/.claude/skills） */
  to?: string;
  /** LLM 二次判定を併用（要 ANTHROPIC_API_KEY） */
  llm?: boolean;
  /** 隔離ディレクトリ名サフィックス（タイムスタンプ等） */
  stamp: string;
}

export interface StagedScan {
  source: string;
  /** 検疫(staging)上のスキル本体パス */
  staged: string;
  id: string;
  results: ScanResult[];
  worst: Severity | null;
  llm: LlmVerdict | null;
  provenance: Provenance;
}

export interface PlaceResult {
  placed: string;
}

const STAGING_ROOT = join(quarantineDir(), "staging");

/** スキルを検疫へ取得し、静的+LLM+出所スキャンを行う（配置はしない）。 */
export async function stageAndScan(source: string, opts: AddOptions): Promise<StagedScan> {
  mkdirSync(STAGING_ROOT, { recursive: true });
  const id = deriveId(source);
  const staged = join(STAGING_ROOT, `${id}-${opts.stamp}`);
  if (existsSync(staged)) rmSync(staged, { recursive: true, force: true });

  await fetchInto(source, staged, id);

  const rules = loadRules();
  const sources = await collect(staged);
  const results = sources.map((s) => scanText(s.content, s.name, rules));
  const worst = worstSeverity(results.flatMap((r) => r.findings));

  // LLM: 灰色(medium+)が出た対象のうち最も重いものを判定（コスト制御）
  let llm: LlmVerdict | null = null;
  if (opts.llm && llmAvailable()) {
    const gray = results
      .filter((r) => r.worst === "high" || r.worst === "medium")
      .sort((a, b) => sev(b.worst) - sev(a.worst));
    if (gray.length > 0) {
      const target = gray[0];
      const src = sources.find((s) => s.name === target.target);
      if (src) llm = await judge(src.content, target.target, target.findings);
    }
  }

  const provenance = await checkProvenance(source);

  return { source, staged, id, results, worst, llm, provenance };
}

/** スキャン結果から「配置をブロックすべきか」を判定する。 */
export function isBlocked(scan: StagedScan): boolean {
  return (
    scan.worst === "high" ||
    scan.llm?.label === "malicious" ||
    scan.provenance.worst === "high"
  );
}

/** スキャン結果から「要確認（警告あり）か」を判定する。 */
export function hasWarnings(scan: StagedScan): boolean {
  return (
    scan.worst === "medium" ||
    scan.llm?.label === "suspicious" ||
    (scan.llm?.mismatch ?? false) ||
    scan.provenance.worst === "warn"
  );
}

/** 検疫上のスキルを配置先へ移動する。配置先に同名があれば失敗（上書きしない）。 */
export function place(scan: StagedScan, opts: AddOptions): PlaceResult {
  const targetDir = opts.to ?? defaultInstallDir(opts.cwd);
  mkdirSync(targetDir, { recursive: true });
  const dest = join(targetDir, scan.id);
  if (existsSync(dest)) {
    throw new Error(`配置先に同名スキルが既に存在します: ${dest}（手動で確認してください）`);
  }
  try {
    renameSync(scan.staged, dest);
  } catch {
    cpSync(scan.staged, dest, { recursive: true });
    rmSync(scan.staged, { recursive: true, force: true });
  }
  return { placed: dest };
}

// ---- 取得 ----

async function fetchInto(source: string, staged: string, id: string): Promise<void> {
  // ローカルパス
  if (!/^https?:\/\//i.test(source) && !source.startsWith("git@") && !parseGitHub(source)) {
    if (!existsSync(source)) throw new Error(`取得元が見つかりません: ${source}`);
    const st = statSync(source);
    if (st.isDirectory()) {
      cpSync(source, staged, { recursive: true });
    } else {
      mkdirSync(staged, { recursive: true });
      cpSync(source, join(staged, basename(source)));
    }
    return;
  }

  // 単体ファイル URL（raw / blob / 一般 URL の .md など）
  const fileUrl = singleFileUrl(source);
  if (fileUrl) {
    const text = await fetchText(fileUrl);
    mkdirSync(staged, { recursive: true });
    writeFileSync(join(staged, fileNameFor(fileUrl)), text, "utf8");
    return;
  }

  // git リポジトリ
  const repo = gitTarget(source);
  if (repo) {
    gitClone(repo.url, repo.ref, staged);
    // .git は走査対象外（collect が SKIP_DIRS で除外するが、配置物から除くため削除）
    rmSync(join(staged, ".git"), { recursive: true, force: true });
    return;
  }

  throw new Error(`取得方法を判別できない取得元です: ${source}`);
}

/** 単体ファイルとして fetch すべき URL なら、その raw URL を返す。リポジトリ clone 対象なら null。 */
function singleFileUrl(source: string): string | null {
  if (!/^https?:\/\//i.test(source)) return null;
  let u: URL;
  try {
    u = new URL(source);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (host === "raw.githubusercontent.com") return source;
  if (host === "github.com") {
    const parts = u.pathname.split("/").filter(Boolean);
    // /owner/repo/blob/<ref>/<path...> は単体ファイル → raw へ変換
    if (parts[2] === "blob" && parts.length >= 5) {
      const [owner, repo, , ref, ...rest] = parts;
      return `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${rest.join("/")}`;
    }
    // /owner/repo や /owner/repo/tree/... はリポジトリ → clone
    return null;
  }
  // 一般 URL: 拡張子がファイルっぽければ単体取得
  if (/\.(md|mdc|toml|json|txt)$/i.test(u.pathname)) return source;
  return source; // 不明な URL も単体取得を試みる（clone 不能なため）
}

function gitTarget(source: string): { url: string; ref?: string } | null {
  if (source.startsWith("git@") || /\.git$/i.test(source)) {
    return { url: source };
  }
  const gh = parseGitHub(source);
  if (gh) return { url: `https://github.com/${gh.owner}/${gh.repo}.git`, ref: gh.ref };
  return null;
}

function gitClone(url: string, ref: string | undefined, dest: string): void {
  if (!hasGit()) throw new Error("git が見つかりません。リポジトリ取得には git が必要です");
  // ブランチ/タグは --branch で浅いクローン。commit SHA はフォールバックで checkout。
  const args = ["clone", "--depth", "1"];
  const looksSha = !!ref && /^[0-9a-f]{7,40}$/i.test(ref);
  if (ref && !looksSha) args.push("--branch", ref);
  args.push(url, dest);
  run("git", args);
  if (ref && looksSha) {
    // 浅いクローンで特定 SHA を取得して checkout
    run("git", ["-C", dest, "fetch", "--depth", "1", "origin", ref]);
    run("git", ["-C", dest, "checkout", ref]);
  }
}

function hasGit(): boolean {
  const r = spawnSync("git", ["--version"], { encoding: "utf8" });
  return r.status === 0;
}

function run(cmd: string, args: string[]): void {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 120_000 });
  if (r.status !== 0) {
    const msg = (r.stderr || r.stdout || r.error?.message || "unknown error").trim().slice(0, 300);
    throw new Error(`${cmd} ${args.slice(0, 2).join(" ")} 失敗: ${msg}`);
  }
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(20_000), redirect: "follow" });
  if (!res.ok) throw new Error(`取得失敗: ${res.status} ${res.statusText} (${url})`);
  const text = await res.text();
  const MAX = 2 * 1024 * 1024;
  if (text.length > MAX) throw new Error(`応答が大きすぎます (${text.length} bytes)`);
  return text;
}

// ---- 補助 ----

function deriveId(source: string): string {
  const gh = parseGitHub(source);
  if (gh) return sanitize(gh.repo);
  if (/^https?:\/\//i.test(source)) {
    try {
      const u = new URL(source);
      const parts = u.pathname.split("/").filter(Boolean);
      const last = parts[parts.length - 1] ?? "";
      if (/^SKILL\.md$/i.test(last) && parts.length >= 2) return sanitize(parts[parts.length - 2]);
      if (last) return sanitize(last.replace(/\.[^.]+$/, ""));
      return sanitize(u.hostname);
    } catch {
      return "downloaded-skill";
    }
  }
  // ローカル
  const st = existsSync(source) ? statSync(source) : null;
  if (st?.isFile()) return sanitize(basename(dirname(source)) || "skill");
  return sanitize(basename(source.replace(/\/+$/, "")) || "skill");
}

function fileNameFor(url: string): string {
  try {
    const last = new URL(url).pathname.split("/").filter(Boolean).pop();
    return last && /\.[a-z0-9]+$/i.test(last) ? last : "SKILL.md";
  } catch {
    return "SKILL.md";
  }
}

function sanitize(s: string): string {
  return s.replace(/[^\w.-]/g, "-").replace(/^-+|-+$/g, "") || "skill";
}

function sev(s: Severity | null): number {
  return s === "high" ? 3 : s === "medium" ? 2 : s === "low" ? 1 : 0;
}

export { type Finding };
