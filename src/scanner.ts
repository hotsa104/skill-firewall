import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

export type Severity = "high" | "medium" | "low";

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  patterns: string[];
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  description: string;
  line: number;
  excerpt: string;
}

export interface ScanResult {
  target: string;
  findings: Finding[];
  /** 最も高い severity（findings が空なら null） */
  worst: Severity | null;
}

let cachedRules: Rule[] | null = null;

/** rules.yaml をモジュール位置を基点に探索して読み込む（ビルド後の dist からも遡れる）。 */
export function loadRules(explicitPath?: string): Rule[] {
  if (explicitPath) {
    return parseRules(readFileSync(explicitPath, "utf8"));
  }
  if (cachedRules) return cachedRules;

  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "rules", "rules.yaml"), // src 実行時
    join(here, "..", "src", "rules", "rules.yaml"), // dist 実行時
    join(here, "..", "rules", "rules.yaml"),
  ];
  const found = candidates.find(existsSync);
  if (!found) {
    throw new Error(`rules.yaml not found. searched: ${candidates.join(", ")}`);
  }
  cachedRules = parseRules(readFileSync(found, "utf8"));
  return cachedRules;
}

interface CompiledRule extends Rule {
  regexes: RegExp[];
}

function parseRules(text: string): Rule[] {
  const parsed = yaml.load(text);
  if (!Array.isArray(parsed)) throw new Error("rules.yaml must be a list");
  const valid: Severity[] = ["high", "medium", "low"];
  for (const r of parsed as Rule[]) {
    if (!r.id || !r.title || !Array.isArray(r.patterns)) {
      throw new Error(`invalid rule (missing id/title/patterns): ${JSON.stringify(r).slice(0, 80)}`);
    }
    if (!valid.includes(r.severity)) {
      throw new Error(`rule '${r.id}' has invalid severity: ${r.severity}`);
    }
    // ロード時に各 pattern をコンパイル検証（不正な regex で実行時クラッシュを防ぐ）
    for (const p of r.patterns) {
      try {
        new RegExp(p, "i");
      } catch (e) {
        throw new Error(`rule '${r.id}' has invalid regex: ${p} (${(e as Error).message})`);
      }
    }
  }
  return parsed as Rule[];
}

function compile(rules: Rule[]): CompiledRule[] {
  return rules.map((r) => ({ ...r, regexes: r.patterns.map((p) => new RegExp(p, "i")) }));
}

/**
 * テキストをスキャンして検出結果を返す。
 * 2段評価: (1) 行単位 — 行番号つきで報告。(2) 全文連結 — 改行で分断して回避する
 * インジェクションを捕捉（line=0 として報告）。LLM は改行をまたいで読むため必須。
 */
export function scanText(content: string, target: string, rules: Rule[]): ScanResult {
  const compiled = compile(rules);
  const lines = content.split(/\r?\n/);
  const findings: Finding[] = [];
  const seen = new Set<string>(); // 同一ルール×同一行の重複抑制

  // (1) 行単位スキャン
  for (const rule of compiled) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (rule.regexes.some((re) => re.test(line))) {
        const key = `${rule.id}:${i + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          description: rule.description,
          line: i + 1,
          excerpt: line.trim().slice(0, 120),
        });
      }
    }
  }

  // (2) 全文連結スキャン（改行→空白に正規化）。行単位で既出のルールは追加しない。
  const flat = content.replace(/\s+/g, " ");
  for (const rule of compiled) {
    const alreadyFound = findings.some((f) => f.ruleId === rule.id);
    if (alreadyFound) continue;
    if (rule.regexes.some((re) => re.test(flat))) {
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        description: rule.description,
        line: 0, // 0 = 改行をまたいで検出（行特定不可）
        excerpt: "(改行をまたいで検出 — 指示が複数行に分割されている可能性)",
      });
    }
  }

  return { target, findings, worst: worstSeverity(findings) };
}

const ORDER: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

export function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (worst === null || ORDER[f.severity] > ORDER[worst]) worst = f.severity;
  }
  return worst;
}

export { resolve };
