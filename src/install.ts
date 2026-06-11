import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK_MARKER = "skill-firewall";

interface HookCommand {
  type: "command";
  command: string;
  timeout?: number;
}
interface HookMatcher {
  matcher?: string;
  hooks: HookCommand[];
}
interface Settings {
  hooks?: Record<string, HookMatcher[]>;
  [k: string]: unknown;
}

function userSettingsPath(): string {
  return join(homedir(), ".claude", "settings.json");
}

/** ビルド済み cli.js の絶対パスを解決（フックコマンドに埋め込む）。 */
function cliPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "cli.js"); // dist/cli.js と同階層に install.js が出力される
}

function loadSettings(path: string): Settings {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Settings;
  } catch (e) {
    throw new Error(`settings.json をパースできません (${path}): ${(e as Error).message}`);
  }
}

function saveSettings(path: string, data: Settings): void {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) copyFileSync(path, `${path}.skill-firewall.bak`); // 破壊防止バックアップ
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n", "utf8");
}

function hookCommand(quarantine: boolean): string {
  const q = quarantine ? " --quarantine" : "";
  return `node "${cliPath()}" hook${q}`; // パスにスペースがあっても安全なよう quote
}

/** SessionStart フックを user settings に登録する。既存設定はマージし、重複登録は防ぐ。 */
export function installHook(opts: { quarantine: boolean }): { path: string; command: string } {
  const path = userSettingsPath();
  const settings = loadSettings(path);
  settings.hooks ??= {};
  settings.hooks.SessionStart ??= [];

  // 既存の skill-firewall エントリを除去（再インストール・設定変更に対応）
  settings.hooks.SessionStart = settings.hooks.SessionStart
    .map((m) => ({ ...m, hooks: m.hooks.filter((h) => !h.command.includes(HOOK_MARKER)) }))
    .filter((m) => m.hooks.length > 0);

  const command = hookCommand(opts.quarantine);
  settings.hooks.SessionStart.push({
    matcher: "startup|clear",
    hooks: [{ type: "command", command, timeout: 30 }],
  });

  saveSettings(path, settings);
  return { path, command };
}

/** skill-firewall の SessionStart フックを除去する。 */
export function uninstallHook(): { path: string; removed: boolean } {
  const path = userSettingsPath();
  if (!existsSync(path)) return { path, removed: false };
  const settings = loadSettings(path);
  if (!settings.hooks?.SessionStart) return { path, removed: false };

  const before = JSON.stringify(settings.hooks.SessionStart);
  settings.hooks.SessionStart = settings.hooks.SessionStart
    .map((m) => ({ ...m, hooks: m.hooks.filter((h) => !h.command.includes(HOOK_MARKER)) }))
    .filter((m) => m.hooks.length > 0);
  const removed = JSON.stringify(settings.hooks.SessionStart) !== before;

  if (removed) saveSettings(path, settings);
  return { path, removed };
}

export { userSettingsPath };
