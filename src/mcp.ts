import { basename } from "node:path";

/**
 * .mcp.json 本格対応。
 *
 * .mcp.json は MCP サーバ定義（command / args / env / url）を持つ JSON。
 * 生 JSON のまま regex を当てるとキー/配列で指示が分断され検出漏れする。
 * そこで command+args を1行に連結し env キー=値・url を平文化して、
 * 既存ルール（remote-code-execution / credential-access / data-exfiltration 等）が
 * 「実際に起動されるコマンド」に当たるようにする。
 */

export function isMcpFile(name: string): boolean {
  return basename(name).toLowerCase() === ".mcp.json";
}

interface McpServer {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
}

/**
 * .mcp.json の中身を、スキャン可能な平文行に変換する。
 * パース不能なら null（呼び出し側は生テキストのスキャンにフォールバック）。
 */
export function flattenMcp(content: string): string | null {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return null;
  }
  const servers = extractServers(data);
  if (!servers) return null;

  const lines: string[] = ["# mcp servers (flattened by skill-firewall)"];
  for (const [name, raw] of Object.entries(servers)) {
    const s = (raw ?? {}) as McpServer;
    const cmd = typeof s.command === "string" ? s.command : "";
    const args = Array.isArray(s.args) ? s.args.filter((a) => typeof a === "string").join(" ") : "";
    if (cmd || args) lines.push(`mcp ${name} command: ${cmd} ${args}`.trim());
    if (typeof s.url === "string") lines.push(`mcp ${name} url: ${s.url}`);
    if (s.env && typeof s.env === "object") {
      for (const [k, v] of Object.entries(s.env as Record<string, unknown>)) {
        lines.push(`mcp ${name} env ${k}=${typeof v === "string" ? v : ""}`);
      }
    }
  }
  return lines.length > 1 ? lines.join("\n") : null;
}

/** mcpServers / servers どちらのキー構成にも対応してサーバ定義の辞書を取り出す。 */
function extractServers(data: unknown): Record<string, unknown> | null {
  if (!data || typeof data !== "object") return null;
  const obj = data as Record<string, unknown>;
  const cand = obj.mcpServers ?? obj.servers;
  if (cand && typeof cand === "object" && !Array.isArray(cand)) {
    return cand as Record<string, unknown>;
  }
  return null;
}
