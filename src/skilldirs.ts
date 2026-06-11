import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname, basename } from "node:path";
import { collect, type Source } from "./collect.js";

export interface SkillUnit {
  /** スキルの識別名（SKILL.md を含む親ディレクトリ名、なければファイル名） */
  id: string;
  /** スキャン対象ファイルの絶対パス */
  file: string;
  /** 隔離時に退避する単位（スキルフォルダ or 単独ファイル） */
  root: string;
  content: string;
}

/**
 * Claude Code の既知スキルディレクトリを列挙する。
 * - プロジェクト: <cwd>/.claude/skills
 * - ユーザー: ~/.claude/skills, ~/.config/claude/skills
 */
export function knownSkillDirs(cwd: string): string[] {
  const home = homedir();
  const candidates = [
    join(cwd, ".claude", "skills"),
    join(home, ".claude", "skills"),
    join(home, ".config", "claude", "skills"),
  ];
  // 重複排除しつつ存在するディレクトリのみ
  return [...new Set(candidates)].filter((d) => existsSync(d) && statSync(d).isDirectory());
}

/**
 * `add` で承認済みスキルを配置する既定ディレクトリ。
 * プロジェクトに .claude/ があればプロジェクトの skills、なければユーザーの ~/.claude/skills。
 */
export function defaultInstallDir(cwd: string): string {
  const projClaude = join(cwd, ".claude");
  if (existsSync(projClaude) && statSync(projClaude).isDirectory()) {
    return join(projClaude, "skills");
  }
  return join(homedir(), ".claude", "skills");
}

/** 指定ディレクトリ群からスキャン対象スキルを収集する。 */
export async function collectSkills(dirs: string[]): Promise<SkillUnit[]> {
  const units: SkillUnit[] = [];
  for (const dir of dirs) {
    let sources: Source[];
    try {
      sources = await collect(dir);
    } catch {
      continue; // スキャン対象なしは無視
    }
    for (const s of sources) {
      units.push(toUnit(s));
    }
  }
  return units;
}

function toUnit(s: Source): SkillUnit {
  const isSkillMd = basename(s.name).toUpperCase() === "SKILL.MD";
  // SKILL.md は親フォルダ全体が1スキル。それ以外は単独ファイルを単位とする。
  const root = isSkillMd ? dirname(s.name) : s.name;
  const id = basename(root);
  return { id, file: s.name, root, content: s.content };
}
