import { loadRules, scanText, type ScanResult, type Severity } from "./scanner.js";
import { knownSkillDirs, collectSkills, type SkillUnit } from "./skilldirs.js";
import { isAllowed } from "./allowlist.js";
import { quarantine, type QuarantineRecord } from "./quarantine.js";
import { judge, llmAvailable, type LlmVerdict } from "./llm.js";

export interface SkillVerdict {
  unit: SkillUnit;
  result: ScanResult;
  worst: Severity | null;
  allowed: boolean;
  quarantined?: QuarantineRecord;
  /** LLM 二次判定（opt-in。未実行・スキップ時は undefined / null） */
  llm?: LlmVerdict | null;
}

export interface SkillScanReport {
  dirs: string[];
  scanned: number;
  verdicts: SkillVerdict[];
  flagged: SkillVerdict[]; // allowlist 済みを除く、medium 以上
}

export interface SkillScanOptions {
  cwd: string;
  /** HIGH 検出かつ未承認のスキルを隔離する */
  quarantine?: boolean;
  /** 隔離ディレクトリ名サフィックス（タイムスタンプ等）。quarantine 時必須 */
  stamp?: string;
  /** LLM 二次判定を有効化（要 ANTHROPIC_API_KEY。flagged のみに限定実行＝コスト制御） */
  llm?: boolean;
}

/** 既知スキルディレクトリを走査し、各スキルを評価する（hook と scan-skills 共通ロジック）。 */
export async function scanSkills(opts: SkillScanOptions): Promise<SkillScanReport> {
  const rules = loadRules();
  const dirs = knownSkillDirs(opts.cwd);
  const units = await collectSkills(dirs);

  const verdicts: SkillVerdict[] = units.map((unit) => {
    const result = scanText(unit.content, unit.file, rules);
    return { unit, result, worst: result.worst, allowed: isAllowed(unit.content) };
  });

  const flagged = verdicts.filter(
    (v) => !v.allowed && (v.worst === "high" || v.worst === "medium")
  );

  // LLM 二次判定: 灰色(=flagged)のみ。クリーンと allowlist 済みはコスト制御のためスキップ。
  if (opts.llm && llmAvailable() && flagged.length > 0) {
    await Promise.all(
      flagged.map(async (v) => {
        v.llm = await judge(v.unit.content, v.unit.file, v.result.findings);
      })
    );
  }

  if (opts.quarantine) {
    const stamp = opts.stamp ?? "unknown";
    for (const v of flagged) {
      if (v.worst === "high") {
        const reason = v.result.findings
          .filter((f) => f.severity === "high")
          .map((f) => `${f.ruleId} (line ${f.line})`)
          .join(", ");
        try {
          v.quarantined = quarantine(v.unit.root, v.unit.id, reason, stamp);
        } catch {
          // 隔離失敗は警告に留める（権限等）。検出自体は報告される
        }
      }
    }
  }

  return { dirs, scanned: units.length, verdicts, flagged };
}
