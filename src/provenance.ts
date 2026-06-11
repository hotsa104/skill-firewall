/**
 * 出所チェック（F-3.3）+ 時間クールダウン（F-2.4）。
 *
 * スキルの取得元の素性を確認する:
 *  - GitHub リポジトリ/メンテナの実在（GitHub API）
 *  - バージョン固定（commit SHA / タグ）か main 追従か
 *  - 公開/最終更新の新しさ（pnpm 11 方式の「寝かせ」: 直近 N 時間のものは警告）
 *
 * 依存ゼロ: Node 組込み fetch のみ。GitHub トークンは任意（GITHUB_TOKEN / GH_TOKEN）で
 * レート制限を緩和できるが、無くても動く。ネットワーク不可・404 でも例外を投げず notes で返す。
 */

export type ProvLevel = "info" | "warn" | "high";

export interface ProvenanceNote {
  level: ProvLevel;
  message: string;
}

export interface GitHubRepoMeta {
  fullName: string;
  ownerType: string; // "User" | "Organization"
  createdAt: string;
  pushedAt: string;
  stars: number;
  archived: boolean;
  fork: boolean;
  defaultBranch: string;
}

export interface Provenance {
  source: string;
  kind: "github" | "url" | "npm" | "local" | "unknown";
  ref?: string;
  /** ref が commit SHA かバージョンタグ（=再現可能に固定）か。floating の逆。 */
  pinned?: boolean;
  exists?: boolean;
  repo?: GitHubRepoMeta;
  /** 取得元の新しさ（時間）。github=最終 push からの経過、npm=公開からの経過。 */
  ageHours?: number;
  notes: ProvenanceNote[];
  worst: ProvLevel;
}

export interface ProvenanceOptions {
  /** 直近この時間内の更新/公開を警告（既定: 24h。env SKILL_FIREWALL_COOLDOWN_HOURS で上書き）。 */
  cooldownHours?: number;
  githubToken?: string;
  timeoutMs?: number;
  /** 経過時間計算の基準時刻（テスト用。既定: 現在時刻）。 */
  now?: Date;
}

const ORDER: Record<ProvLevel, number> = { info: 0, warn: 1, high: 2 };

function cooldown(opts: ProvenanceOptions): number {
  if (typeof opts.cooldownHours === "number") return opts.cooldownHours;
  const env = process.env.SKILL_FIREWALL_COOLDOWN_HOURS;
  const n = env ? Number(env) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : 24;
}

/** GitHub の各種 URL / shorthand を owner/repo/ref に分解する。GitHub でなければ null。 */
export function parseGitHub(source: string): { owner: string; repo: string; ref?: string } | null {
  // github:owner/repo[#ref] の shorthand。
  // 素の owner/repo はローカル相対パス(dir/file)と区別できないため github: 接頭辞を必須にする。
  const short = /^github:([\w.-]+)\/([\w.-]+?)(?:#([\w./-]+))?$/i;
  if (!/^https?:\/\//i.test(source)) {
    const m = short.exec(source);
    if (m) return { owner: m[1], repo: stripGit(m[2]), ref: m[3] };
    return null;
  }
  let u: URL;
  try {
    u = new URL(source);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  const parts = u.pathname.split("/").filter(Boolean);
  if (host === "github.com") {
    if (parts.length < 2) return null;
    const [owner, repoRaw, kind, ref] = parts;
    const repo = stripGit(repoRaw);
    // /owner/repo/tree|blob/<ref>/...
    if ((kind === "tree" || kind === "blob") && ref) return { owner, repo, ref };
    return { owner, repo };
  }
  if (host === "raw.githubusercontent.com") {
    // raw.githubusercontent.com/<owner>/<repo>/<ref>/<path...>
    if (parts.length < 3) return null;
    return { owner: parts[0], repo: stripGit(parts[1]), ref: parts[2] };
  }
  return null;
}

function stripGit(s: string): string {
  return s.replace(/\.git$/i, "");
}

/** ref が固定（commit SHA / バージョンタグ）か。branch 名や HEAD は floating(=false)。 */
export function isPinned(ref: string | undefined): boolean {
  if (!ref) return false;
  if (/^[0-9a-f]{7,40}$/i.test(ref)) return true; // commit SHA
  if (/^v?\d+\.\d+(\.\d+)?([-.][\w.]+)?$/.test(ref)) return true; // セマンティックなタグ
  return false;
}

/** 取得元の素性を調べる。 */
export async function checkProvenance(source: string, opts: ProvenanceOptions = {}): Promise<Provenance> {
  const now = opts.now ?? new Date();
  const coolH = cooldown(opts);
  const notes: ProvenanceNote[] = [];

  // ローカルパス
  if (!/^https?:\/\//i.test(source) && !parseGitHub(source) && !source.startsWith("npm:")) {
    return finalize({ source, kind: "local", notes });
  }

  const gh = parseGitHub(source);
  if (gh) {
    const ref = gh.ref;
    const pinned = isPinned(ref);
    if (!ref) {
      notes.push({ level: "warn", message: "ref 未指定（デフォルトブランチ追従）。承認後に内容が変わりうる" });
    } else if (!pinned) {
      notes.push({ level: "warn", message: `ref '${ref}' はブランチ追従（固定でない）。commit SHA かタグでの固定を推奨` });
    } else {
      notes.push({ level: "info", message: `ref '${ref}' で固定（再現可能）` });
    }

    const meta = await fetchGitHubRepo(gh.owner, gh.repo, opts);
    if (meta === "notfound") {
      notes.push({ level: "high", message: `GitHub リポジトリが存在しません: ${gh.owner}/${gh.repo}` });
      return finalize({ source, kind: "github", ref, pinned, exists: false, notes });
    }
    if (meta === "error") {
      notes.push({ level: "info", message: "GitHub API に到達できず実在確認をスキップ（オフライン/レート制限）" });
      return finalize({ source, kind: "github", ref, pinned, notes });
    }
    if (meta.archived) notes.push({ level: "warn", message: "アーカイブ済みリポジトリ（メンテナンスされていない可能性）" });
    if (meta.fork) notes.push({ level: "warn", message: "フォークリポジトリ（上流のなりすましに注意）" });
    if (meta.stars < 5) notes.push({ level: "info", message: `star ${meta.stars} 件（実績が乏しい）` });

    const ageHours = hoursSince(meta.pushedAt, now);
    if (ageHours !== null && ageHours < coolH) {
      notes.push({ level: "warn", message: `最終更新が ${ageHours.toFixed(1)}h 前（クールダウン ${coolH}h 未満）。寝かせて再確認を推奨` });
    }
    return finalize({ source, kind: "github", ref, pinned, exists: true, repo: meta, ageHours: ageHours ?? undefined, notes });
  }

  // npm パッケージ
  if (source.startsWith("npm:")) {
    const name = source.slice(4);
    const npm = await fetchNpmMeta(name, opts);
    if (npm === "notfound") {
      notes.push({ level: "high", message: `npm に存在しないパッケージ: ${name}` });
      return finalize({ source, kind: "npm", exists: false, notes });
    }
    if (npm === "error") {
      notes.push({ level: "info", message: "npm レジストリに到達できず確認をスキップ" });
      return finalize({ source, kind: "npm", notes });
    }
    const ageHours = hoursSince(npm.latestPublishedAt, now);
    if (ageHours !== null && ageHours < coolH) {
      notes.push({ level: "warn", message: `最新版の公開が ${ageHours.toFixed(1)}h 前（クールダウン ${coolH}h 未満）` });
    }
    return finalize({ source, kind: "npm", exists: true, ageHours: ageHours ?? undefined, notes });
  }

  // その他の URL
  let host = "";
  try {
    host = new URL(source).hostname;
  } catch {
    /* noop */
  }
  notes.push({ level: "info", message: `GitHub/npm 以外の取得元（${host || "不明なホスト"}）。実在・固定の自動確認はできません` });
  return finalize({ source, kind: "url", notes });
}

function finalize(p: Omit<Provenance, "worst">): Provenance {
  let worst: ProvLevel = "info";
  for (const n of p.notes) if (ORDER[n.level] > ORDER[worst]) worst = n.level;
  return { ...p, worst };
}

function hoursSince(iso: string | undefined, now: Date): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return (now.getTime() - t) / 3_600_000;
}

function ghToken(opts: ProvenanceOptions): string | undefined {
  return opts.githubToken ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
}

async function fetchGitHubRepo(
  owner: string,
  repo: string,
  opts: ProvenanceOptions
): Promise<GitHubRepoMeta | "notfound" | "error"> {
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "skill-firewall",
  };
  const tok = ghToken(opts);
  if (tok) headers.authorization = `Bearer ${tok}`;
  let res: Response;
  try {
    res = await fetch(`https://api.github.com/repos/${enc(owner)}/${enc(repo)}`, {
      headers,
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
    });
  } catch {
    return "error";
  }
  if (res.status === 404) return "notfound";
  if (!res.ok) return "error";
  let d: Record<string, unknown>;
  try {
    d = (await res.json()) as Record<string, unknown>;
  } catch {
    return "error";
  }
  const ownerObj = (d.owner ?? {}) as Record<string, unknown>;
  return {
    fullName: String(d.full_name ?? `${owner}/${repo}`),
    ownerType: String(ownerObj.type ?? "unknown"),
    createdAt: String(d.created_at ?? ""),
    pushedAt: String(d.pushed_at ?? ""),
    stars: typeof d.stargazers_count === "number" ? d.stargazers_count : 0,
    archived: d.archived === true,
    fork: d.fork === true,
    defaultBranch: String(d.default_branch ?? "main"),
  };
}

async function fetchNpmMeta(
  name: string,
  opts: ProvenanceOptions
): Promise<{ latestPublishedAt?: string } | "notfound" | "error"> {
  let res: Response;
  try {
    res = await fetch(`https://registry.npmjs.org/${name.split("/").map(enc).join("/")}`, {
      headers: { accept: "application/json", "user-agent": "skill-firewall" },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
    });
  } catch {
    return "error";
  }
  if (res.status === 404) return "notfound";
  if (!res.ok) return "error";
  let d: Record<string, unknown>;
  try {
    d = (await res.json()) as Record<string, unknown>;
  } catch {
    return "error";
  }
  const distTags = (d["dist-tags"] ?? {}) as Record<string, unknown>;
  const latest = typeof distTags.latest === "string" ? distTags.latest : undefined;
  const time = (d.time ?? {}) as Record<string, unknown>;
  const latestPublishedAt = latest && typeof time[latest] === "string" ? (time[latest] as string) : undefined;
  return { latestPublishedAt };
}

function enc(s: string): string {
  return encodeURIComponent(s);
}
