#!/usr/bin/env node
import { loadRules, scanText, type ScanResult, type Severity, type Finding } from "./scanner.js";
import { collect } from "./collect.js";
import { runHook } from "./hook.js";
import { scanSkills } from "./skillscan.js";
import { installHook, uninstallHook } from "./install.js";
import { allow, listAllowed, allowlistPath } from "./allowlist.js";
import { judge, llmAvailable, type LlmVerdict } from "./llm.js";
import { checkProvenance, type Provenance, type ProvLevel } from "./provenance.js";
import { stageAndScan, isBlocked, hasWarnings, place, type StagedScan, type AddOptions } from "./add.js";
import { listQuarantined, quarantineDir } from "./quarantine.js";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  green: "\x1b[32m",
  gray: "\x1b[90m",
};
const useColor = process.stdout.isTTY;
const c = (color: keyof typeof C, s: string) => (useColor ? `${C[color]}${s}${C.reset}` : s);

const SEV_LABEL: Record<Severity, string> = {
  high: "HIGH",
  medium: "MEDIUM",
  low: "INFO",
};
const SEV_COLOR: Record<Severity, keyof typeof C> = {
  high: "red",
  medium: "yellow",
  low: "blue",
};

const HELP = `${c("bold", "skill-firewall")} — scan AI agent skills for malicious instructions

${c("bold", "Usage:")}
  skill-firewall scan <path|url>     ファイル / ディレクトリ / URL の SKILL.md をスキャン
  skill-firewall scan-skills         既知の Claude Code スキルディレクトリを一括スキャン
  skill-firewall provenance <url>    取得元の素性確認（GitHub/npm 実在・固定・新しさ）
  skill-firewall add <src>           検疫付きインストール（取得→隔離スキャン→安全なら配置）
  skill-firewall quarantine          隔離中・配置保留中のスキルを一覧表示
  skill-firewall allow <path>        スキルを承認リストに追加（以降の警告を抑制）
  skill-firewall allow --list        承認済みスキルを一覧表示
  skill-firewall install-hook        SessionStart フックを ~/.claude/settings.json に登録
  skill-firewall uninstall-hook      フックを解除
  skill-firewall hook                （内部用）SessionStart フックとして実行
  skill-firewall --help

${c("bold", "Options:")}
  --json         結果を JSON で出力（scan / scan-skills）
  --quiet        検出がなければ何も表示しない（scan / scan-skills）
  --quarantine   HIGH 検出かつ未承認のスキルを隔離（scan-skills / install-hook）
  --llm          灰色(medium 以上)のみ Claude API で二次判定（要 ANTHROPIC_API_KEY）
  --to <dir>     add の配置先 skills ディレクトリを指定
  --force        add で警告/危険があっても配置を強行
  --yes, -y      add の確認プロンプトに自動で yes（要確認止まりを承認）

${c("bold", "Env:")}
  ANTHROPIC_API_KEY     --llm 判定に使用（未設定なら静かにスキップ）
  SKILL_FIREWALL_MODEL  --llm 判定のモデル（既定: claude-opus-4-8）

${c("bold", "Exit codes:")}
  0  クリーン、または low(INFO) のみ
  1  medium 検出（警告）
  2  high 検出（要確認）
  3  実行エラー

${c("bold", "Examples:")}
  skill-firewall scan ./my-skill/SKILL.md
  skill-firewall scan-skills
  skill-firewall install-hook
`;

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    process.exit(argv.length === 0 ? 3 : 0);
  }

  const json = argv.includes("--json");
  const quiet = argv.includes("--quiet");
  const quarantineFlag = argv.includes("--quarantine");
  const listFlag = argv.includes("--list");
  const llmFlag = argv.includes("--llm");
  const forceFlag = argv.includes("--force");
  const yesFlag = argv.includes("--yes") || argv.includes("-y");
  const toValue = optValue(argv, "--to");

  // 位置引数を抽出（--to の値トークンは消費して除外する）。
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("-")) {
      if (a === "--to" && argv[i + 1] && !argv[i + 1].startsWith("-")) i++;
      continue;
    }
    positionals.push(a);
  }
  const cmd = positionals[0];
  const target = positionals[1];

  const guard = (p: Promise<void>) =>
    p.catch((err) => fail(err instanceof Error ? err.message : String(err)));

  switch (cmd) {
    case "scan":
      if (!target) fail("scan requires a <path|url> argument");
      guard(run(target, { json, quiet, llm: llmFlag }));
      break;
    case "scan-skills":
      guard(runScanSkills({ json, quiet, quarantine: quarantineFlag, llm: llmFlag }));
      break;
    case "provenance":
      if (!target) fail("provenance requires a <url|owner/repo|npm:pkg> argument");
      guard(runProvenance(target, { json }));
      break;
    case "add":
      if (!target) fail("add requires a <path|url|github:owner/repo> argument");
      guard(runAdd(target, { json, llm: llmFlag, to: toValue, force: forceFlag, yes: yesFlag }));
      break;
    case "quarantine":
      runQuarantineList(json);
      break;
    case "hook":
      guard(runHook({ quarantine: quarantineFlag }));
      break;
    case "install-hook":
      runInstall(quarantineFlag);
      break;
    case "uninstall-hook":
      runUninstall();
      break;
    case "allow":
      runAllow(listFlag ? null : target, listFlag);
      break;
    default:
      fail(`unknown command: ${cmd ?? "(none)"}. run --help`);
  }
}

async function runScanSkills(opts: { json: boolean; quiet: boolean; quarantine: boolean; llm: boolean }): Promise<void> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  warnLlmUnavailable(opts.llm);
  const rep = await scanSkills({ cwd: process.cwd(), quarantine: opts.quarantine, stamp, llm: opts.llm });

  if (opts.json) {
    console.log(JSON.stringify(rep, null, 2));
  } else if (!(opts.quiet && rep.flagged.length === 0)) {
    if (rep.dirs.length === 0) {
      console.log(c("gray", "スキャン対象のスキルディレクトリが見つかりませんでした。"));
    } else {
      console.log(c("gray", `対象: ${rep.dirs.join(", ")}`));
      const llmByTarget = new Map(rep.flagged.map((v) => [v.result.target, v.llm ?? null]));
      report(rep.verdicts.map((v) => v.result), rep.scanned, llmByTarget);
      for (const v of rep.flagged) {
        if (v.quarantined) console.log(c("red", `  → 隔離: ${v.unit.id} → ${v.quarantined.to}`));
      }
    }
  }

  const high = rep.flagged.some((v) => v.worst === "high");
  const med = rep.flagged.some((v) => v.worst === "medium");
  process.exit(high ? 2 : med ? 1 : 0);
}

function runInstall(quarantine: boolean): void {
  const { path, command } = installHook({ quarantine });
  console.log(c("green", "✓ SessionStart フックを登録しました"));
  console.log(c("gray", `  settings: ${path}`));
  console.log(c("gray", `  command : ${command}`));
  if (quarantine) console.log(c("yellow", "  モード: HIGH 検出時に自動隔離"));
  else console.log(c("gray", "  モード: 警告のみ（隔離は --quarantine で有効化）"));
  console.log(c("gray", "  次回セッション開始時から有効になります。解除: skill-firewall uninstall-hook"));
}

function runUninstall(): void {
  const { path, removed } = uninstallHook();
  if (removed) console.log(c("green", `✓ フックを解除しました (${path})`));
  else console.log(c("gray", `skill-firewall フックは登録されていません (${path})`));
}

function runAllow(target: string | null, list: boolean): void {
  if (list) {
    const entries = listAllowed();
    if (entries.length === 0) console.log(c("gray", "承認済みスキルはありません。"));
    else {
      console.log(c("bold", `承認済みスキル (${allowlistPath()}):`));
      for (const e of entries) console.log(`  ${e.id}  ${c("gray", e.hash.slice(0, 12))}  ${c("gray", e.approvedAt)}`);
    }
    process.exit(0);
  }
  if (!target) fail("allow requires a <path> argument (または --list)");
  let content: string;
  try {
    content = readFileSync(target, "utf8");
  } catch (e) {
    fail(`ファイルを読めません: ${target} (${(e as Error).message})`);
  }
  const entry = allow(content!, target, new Date().toISOString());
  console.log(c("green", `✓ 承認しました: ${target}`));
  console.log(c("gray", `  sha256: ${entry.hash}`));
  process.exit(0);
}

async function run(target: string, opts: { json: boolean; quiet: boolean; llm: boolean }): Promise<void> {
  const rules = loadRules();
  const sources = await collect(target);
  const results: ScanResult[] = sources.map((s) => scanText(s.content, s.name, rules));

  const allFindings = results.flatMap((r) => r.findings);
  const hasHigh = allFindings.some((f) => f.severity === "high");
  const hasMedium = allFindings.some((f) => f.severity === "medium");

  // LLM 二次判定: medium 以上が出た対象のみ（コスト制御）。
  const llmByTarget = new Map<string, LlmVerdict | null>();
  warnLlmUnavailable(opts.llm);
  if (opts.llm && llmAvailable()) {
    const gray = results.filter((r) => r.worst === "high" || r.worst === "medium");
    await Promise.all(
      gray.map(async (r) => {
        const src = sources.find((s) => s.name === r.target);
        if (src) llmByTarget.set(r.target, await judge(src.content, r.target, r.findings));
      })
    );
  }

  if (opts.json) {
    const enriched = results.map((r) => ({ ...r, llm: llmByTarget.get(r.target) ?? null }));
    console.log(JSON.stringify({ scanned: sources.length, results: enriched }, null, 2));
  } else if (!(opts.quiet && allFindings.length === 0)) {
    report(results, sources.length, llmByTarget);
  }

  process.exit(hasHigh ? 2 : hasMedium ? 1 : 0);
}

/** --llm 指定だが API キーが無い場合に一度だけ注意を出す（静かにスキップはするが意図とのズレを伝える）。 */
function warnLlmUnavailable(llm: boolean): void {
  if (llm && !llmAvailable()) {
    console.error(c("gray", "注: --llm 指定ですが ANTHROPIC_API_KEY が未設定のため LLM 判定をスキップします。"));
  }
}

function report(
  results: ScanResult[],
  scanned: number,
  llmByTarget?: Map<string, LlmVerdict | null>
): void {
  const withFindings = results.filter((r) => r.findings.length > 0);

  if (withFindings.length === 0) {
    console.log(c("green", `✓ クリーン`) + c("gray", ` — ${scanned} 件のスキルをスキャン、検出なし`));
    return;
  }

  for (const r of withFindings) {
    console.log("");
    console.log(c("bold", r.target));
    const ordered = [...r.findings].sort(
      (a, b) => rank(b.severity) - rank(a.severity) || a.line - b.line
    );
    for (const f of ordered) {
      printFinding(f);
    }
    const v = llmByTarget?.get(r.target);
    if (v) printLlm(v);
  }

  // サマリ
  const all = results.flatMap((r) => r.findings);
  const h = all.filter((f) => f.severity === "high").length;
  const m = all.filter((f) => f.severity === "medium").length;
  const l = all.filter((f) => f.severity === "low").length;
  console.log("");
  console.log(
    c("bold", "結果: ") +
      `${scanned} スキル中 ${withFindings.length} 件に検出 — ` +
      c("red", `HIGH ${h}`) + " / " +
      c("yellow", `MEDIUM ${m}`) + " / " +
      c("blue", `INFO ${l}`)
  );
  if (h > 0) {
    console.log(c("red", "→ HIGH 検出。インストールせず内容を確認してください。"));
  } else if (m > 0) {
    console.log(c("yellow", "→ MEDIUM 検出。正当な用途の可能性もあります。該当行を確認してください。"));
  }
}

function printFinding(f: Finding): void {
  const tag = c(SEV_COLOR[f.severity], `[${SEV_LABEL[f.severity]}]`);
  console.log(`  ${tag} ${c("bold", f.title)} ${c("gray", `(${f.ruleId}, line ${f.line})`)}`);
  console.log(`    ${c("gray", f.excerpt)}`);
}

const LLM_COLOR: Record<LlmVerdict["label"], keyof typeof C> = {
  malicious: "red",
  suspicious: "yellow",
  benign: "green",
};

function printLlm(v: LlmVerdict): void {
  const tag = c(LLM_COLOR[v.label], `[LLM:${v.label}]`);
  const mismatch = v.mismatch ? c("red", " 目的乖離あり") : "";
  console.log(`  ${tag} ${c("gray", `confidence=${v.confidence}${mismatch} (${v.model})`)}`);
  if (v.declaredPurpose) console.log(`    ${c("gray", `宣言目的: ${v.declaredPurpose}`)}`);
  if (v.reasoning) console.log(`    ${c("gray", v.reasoning)}`);
}

function rank(s: Severity): number {
  return s === "high" ? 3 : s === "medium" ? 2 : 1;
}

async function runProvenance(target: string, opts: { json: boolean }): Promise<void> {
  const prov = await checkProvenance(target);
  if (opts.json) {
    console.log(JSON.stringify(prov, null, 2));
  } else {
    printProvenance(prov);
  }
  process.exit(prov.worst === "high" ? 2 : prov.worst === "warn" ? 1 : 0);
}

const PROV_COLOR: Record<ProvLevel, keyof typeof C> = { info: "gray", warn: "yellow", high: "red" };
const PROV_TAG: Record<ProvLevel, string> = { info: "INFO", warn: "WARN", high: "RISK" };

function printProvenance(p: Provenance): void {
  console.log(c("bold", `出所: ${p.source}`) + c("gray", ` [${p.kind}]`));
  if (p.repo) {
    console.log(
      c("gray", `  ${p.repo.fullName} — ${p.repo.ownerType} / star ${p.repo.stars} / 既定ブランチ ${p.repo.defaultBranch}`)
    );
  }
  if (p.ref) console.log(c("gray", `  ref: ${p.ref} (${p.pinned ? "固定" : "追従"})`));
  for (const n of p.notes) {
    console.log(`  ${c(PROV_COLOR[n.level], `[${PROV_TAG[n.level]}]`)} ${n.message}`);
  }
}

function runQuarantineList(json: boolean): void {
  const entries = listQuarantined();
  if (json) {
    console.log(JSON.stringify({ dir: quarantineDir(), entries }, null, 2));
    process.exit(0);
  }
  if (entries.length === 0) {
    console.log(c("gray", `隔離中のスキルはありません (${quarantineDir()})`));
    process.exit(0);
  }
  console.log(c("bold", `隔離ディレクトリ: ${quarantineDir()}`));
  for (const e of entries) {
    const tag = e.kind === "quarantined" ? c("red", "[隔離]") : c("yellow", "[保留]");
    console.log(`  ${tag} ${e.name}`);
    if (e.reason) console.log(`    ${c("gray", `理由: ${e.reason}`)}`);
    console.log(`    ${c("gray", e.path)}`);
  }
  console.log("");
  console.log(c("gray", "確認後に使うには内容を精査し、安全なら skills ディレクトリへ手動移動 or `skill-firewall add --force`。"));
  console.log(c("gray", "破棄するには各パスを削除してください。"));
  process.exit(0);
}

/** `--name value` または `--name=value` 形式のオプション値を取り出す。 */
function optValue(argv: string[], name: string): string | undefined {
  const eq = argv.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const i = argv.indexOf(name);
  if (i >= 0 && i + 1 < argv.length && !argv[i + 1].startsWith("-")) return argv[i + 1];
  return undefined;
}

async function runAdd(
  source: string,
  opts: { json: boolean; llm: boolean; to?: string; force: boolean; yes: boolean }
): Promise<void> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  warnLlmUnavailable(opts.llm);
  const addOpts: AddOptions = { cwd: process.cwd(), to: opts.to, llm: opts.llm, stamp };

  let scan: StagedScan;
  try {
    scan = await stageAndScan(source, addOpts);
  } catch (e) {
    fail(`取得/スキャンに失敗: ${(e as Error).message}`);
  }

  const blocked = isBlocked(scan!);
  const warn = hasWarnings(scan!);

  if (!opts.json) printAddReport(scan!, blocked, warn);

  // 配置するか決定（安全側デフォルト: 危険は --force、要確認は --yes/対話/--force）
  let decision: "placed" | "quarantined" = "quarantined";
  let placedPath: string | undefined;
  let approve = false;
  if (blocked) {
    approve = opts.force;
  } else if (warn) {
    approve = opts.force || opts.yes || (await confirm("要確認の検出があります。配置しますか?"));
  } else {
    approve = true; // クリーン
  }

  if (approve) {
    try {
      placedPath = place(scan!, addOpts).placed;
      decision = "placed";
    } catch (e) {
      if (!opts.json) console.error(c("red", `配置失敗: ${(e as Error).message}`));
    }
  }

  if (opts.json) {
    console.log(JSON.stringify({ ...scan!, blocked, warn, decision, placed: placedPath ?? null }, null, 2));
  } else if (decision === "placed") {
    console.log(c("green", `✓ 配置しました: ${placedPath}`));
  } else {
    console.log(c("yellow", `→ 検疫に保持: ${scan!.staged}`));
    if (blocked) console.log(c("gray", "  危険判定のため未配置。内容確認後に配置するには --force を付けて再実行。"));
    else if (warn) console.log(c("gray", "  要確認のため未配置。承認するには --yes、確認後の強行は --force。"));
    console.log(c("gray", `  破棄するには: rm -rf "${scan!.staged}"`));
  }

  process.exit(decision === "placed" ? 0 : blocked ? 2 : 1);
}

function printAddReport(scan: StagedScan, blocked: boolean, warn: boolean): void {
  console.log(c("bold", `取得元: ${scan.source}`) + c("gray", `  → 検疫: ${scan.staged}`));
  report(
    scan.results,
    scan.results.length,
    scan.llm ? new Map(scan.results.filter((r) => r.worst).map((r) => [r.target, scan.llm])) : undefined
  );
  console.log("");
  printProvenance(scan.provenance);
  console.log("");
  if (blocked) console.log(c("red", "判定: 危険（配置をブロック）"));
  else if (warn) console.log(c("yellow", "判定: 要確認"));
  else console.log(c("green", "判定: クリーン"));
}

/** y/N 確認。非 TTY では false（安全側）。 */
async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const ans = (await rl.question(`${c("yellow", "? ")}${question} [y/N] `)).trim().toLowerCase();
    return ans === "y" || ans === "yes";
  } finally {
    rl.close();
  }
}

function fail(msg: string): never {
  console.error(c("red", "error: ") + msg);
  process.exit(3);
}

main();
