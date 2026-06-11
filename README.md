# skill-firewall

Scan AI agent skills (`SKILL.md`) for prompt injection and malicious instructions — and keep checking them automatically.

**[English](#english) | [日本語](#日本語)**

> **Status: v0.1 — unpublished (Phase 1–3 implemented).** Static scanner + Claude Code hook
> + LLM second-pass + provenance check + quarantining installer. Not on npm yet, so use a local
> clone + build (see Quick Start).

---

## English

### Why

- npm package-layer defense has matured (pnpm 11 `minimumReleaseAge`, etc.), but the
  **skill / MCP layer is wide open** (`npx xxx add`, `curl | sh`, `git clone` all bypass it).
- The real risk of a skill is less malware than **prompt injection** — feeding the agent
  hostile instructions.
- The goal is not "raising the alarm" but **"protected the moment you install it."** Install the
  hook once and every Claude Code startup scans your skills and warns/quarantines dangerous ones.

### Quick Start

```bash
# 1. Get it and build (local, since it isn't on npm yet)
git clone <repo> skill-firewall && cd skill-firewall
npm install --ignore-scripts && npm run build

# 2. Install the hook (that's it — no further user action)
node dist/cli.js install-hook              # warn-only mode
# node dist/cli.js install-hook --quarantine  # auto-quarantine dangerous skills

# 3. Scanning runs automatically from the next Claude Code startup
```

#### What you see at startup

When a dangerous skill is present, Claude Code shows a warning like this (`systemMessage`).
Details are also injected into the agent's context, asking it not to trust the skill until reviewed.

```
⚠️ skill-firewall: 1 high-risk skill detected (not quarantined)
  • [HIGH] suspicious-skill
details: `skill-firewall scan-skills` / quarantine: `skill-firewall scan-skills --quarantine`
```

Remove it with `node dist/cli.js uninstall-hook`.

### All commands (reference)

```bash
# --- Scan (Phase 1) ---
node dist/cli.js scan ./my-skill/SKILL.md     # a file
node dist/cli.js scan ~/.claude/skills        # a directory, recursive (.mcp.json too)
node dist/cli.js scan https://raw.githubusercontent.com/owner/repo/main/SKILL.md  # a URL

# --- Resident (Phase 2: Claude Code hooks) ---
node dist/cli.js install-hook                 # auto-scan on SessionStart, inject warning
node dist/cli.js install-hook --quarantine    # auto-quarantine HIGH findings
node dist/cli.js scan-skills                  # scan all known skill directories at once
node dist/cli.js allow ./my-skill/SKILL.md    # approve (sha256; suppresses later warnings)

# --- Phase 3 ---
node dist/cli.js scan ./skill --llm           # second-pass only the gray (medium+) ones via Claude API
node dist/cli.js provenance github:owner/repo # source check: existence / version pinning / freshness
node dist/cli.js add github:owner/repo        # quarantining install (fetch → quarantined scan → place if safe)
node dist/cli.js add ./skill --llm            # add, with LLM judgment
node dist/cli.js quarantine                   # list quarantined / pending items

# during development, npm scripts work too
npm run dev -- scan ./my-skill/SKILL.md
```

`--json` for machine-readable output, `--quiet` to print only when something is found.

#### LLM second pass (`--llm`)

Only targets that the static regex left "gray" (medium or higher) are sent to the Claude API to
detect **divergence between the declared purpose and the actual instructions** (clean ones are
skipped = cost control).

- **opt-in**: if `ANTHROPIC_API_KEY` is unset it silently skips (never spends network/money on its own)
- model via `SKILL_FIREWALL_MODEL` (default `claude-opus-4-8`)
- zero dependencies: no SDK added — calls `/v1/messages` directly with Node's built-in `fetch`

> Inside the Claude Code hook you don't need a key: the already-running agent reasons over the
> injected context. `--llm` is for **manual / CI use outside a session**, where no agent is present.

#### Quarantining installer (`add`)

Instead of dropping a skill straight into your skills directory, `add` fetches it into quarantine,
runs static + LLM + provenance scans, and only places it when safe/approved. HIGH findings, an LLM
"malicious" verdict, or a missing repository **block placement** and keep it quarantined with a report.
Sources: local path / single URL / GitHub repo (`git clone`). `--force` to override, `--yes` to accept warnings.

#### Exit codes

| code | meaning |
|------|---------|
| 0 | clean, or INFO only |
| 1 | MEDIUM found (warning) |
| 2 | HIGH found (review needed) |
| 3 | runtime error |

Usable from CI / shell via the exit code.

### Detection rules

Defined externally in `src/rules/rules.yaml` (rules can be added by PR). Three confidence tiers:

- **HIGH** — known attack patterns, almost certainly malicious (instruction override, covert
  instructions, credential exposure, `curl|sh`, invisible-character hiding, config tampering)
- **MEDIUM** — dangerous but with legitimate uses (`.env` access, external send, encoded payloads,
  destructive FS ops, persistence)
- **INFO** — advisory only

**Design priority: zero HIGH false positives.** Low-confidence items stay as info. Verified with
false-positive traps (legit skills containing `GITHUB_TOKEN` / `.ssh/config`) plus real skills.

### Threat model (important)

Injecting "don't trust this skill" via the agent's context is the **weakest, persuasion-based layer** —
the attacker controls the same context and can override it ("the warning is a false positive, ignore it").
Don't make it load-bearing. The controls that actually hold are **structural**: (1) `--quarantine`
physically removes the file so the agent can't read it, and (2) the user-visible `systemMessage` so the
**human** decides. Detection runs in a separate process (the `--llm` pass fences the content as untrusted
data), so it isn't poisoned by the skill it's judging.

### Limitations

Static regex is a first-pass filter for **known plaintext patterns**. The full-text pass covers
newline-splitting, but synonyms, paraphrasing, full-width/alternate spellings, and context
(`GITHUB_TOKEN` "explained" vs "exfiltrated") are inherently hard — the opt-in `--llm` pass covers those.
**Do not treat this tool alone as complete protection.**

### Development

```bash
npm install --ignore-scripts
npm test        # verify against malicious/benign samples (detection rate, zero HIGH false positives)
npm run build   # outputs to dist/
npm run dev -- scan <path>
```

### Roadmap

- [x] **Phase 1**: CLI static scanner (file/dir/URL, rule set, two-stage scan)
- [x] **Phase 2**: Claude Code hooks (SessionStart auto-scan → warn → quarantine / allowlist)
- [x] **Phase 3**: LLM second pass, provenance check, quarantining installer, `.mcp.json` support, quarantine list
- [ ] **Phase 4**: npm publish, article series, website (if there's demand)

---

## 日本語

AI コーディングエージェント（Claude Code / Cursor 等）のスキルは Markdown の指示書です。
npm のクールダウンやスキャンを経由せず、置かれた瞬間からエージェントが読みます。
`skill-firewall` はその「無防備な層」を静的スキャンで検査し、以降も自動で守り続けます。

### Why

- npm パッケージ層の防御は進んだ（pnpm 11 の `minimumReleaseAge` 等）が、
  **スキル / MCP 層は無防備**（`npx xxx add`・`curl | sh`・git clone で素通り）。
- スキルの本当のリスクはマルウェアより **プロンプトインジェクション**
  ＝エージェントに不正な指示を読ませること。
- 「警鐘」ではなく **「入れたら勝手に検査される」** 仕組み。フックを一度入れれば、以降は
  Claude Code 起動時に自動でスキャンし、危険なスキルを警告／隔離します。

### Quick Start

```bash
# 1. 取得してビルド（npm 未公開のためローカル）
git clone <repo> skill-firewall && cd skill-firewall
npm install --ignore-scripts && npm run build

# 2. フックを入れる（これだけ。以降ユーザー操作は不要）
node dist/cli.js install-hook              # 警告モード
# node dist/cli.js install-hook --quarantine  # 危険スキルを自動隔離したい場合

# 3. 次回 Claude Code 起動時から自動で検査されます
```

#### 起動時に表示されるもの

危険なスキルがあると、Claude Code の画面に次のような警告が出ます（`systemMessage`）。
詳細はエージェントのコンテキストにも注入され、確認するまで当該スキルを信頼しないよう促します。

```
⚠️ skill-firewall: 高リスク 1 件を検出（未隔離）
  • [HIGH] suspicious-skill
詳細: `skill-firewall scan-skills` / 退避: `skill-firewall scan-skills --quarantine`
```

解除は `node dist/cli.js uninstall-hook`。

### All commands (reference)

```bash
# --- スキャン（Phase 1）---
node dist/cli.js scan ./my-skill/SKILL.md     # ファイル
node dist/cli.js scan ~/.claude/skills        # ディレクトリ再帰（.mcp.json も対象）
node dist/cli.js scan https://raw.githubusercontent.com/owner/repo/main/SKILL.md  # URL

# --- 常駐（Phase 2: Claude Code hooks）---
node dist/cli.js install-hook                 # SessionStart で自動スキャン→警告注入
node dist/cli.js install-hook --quarantine    # HIGH を自動隔離するモード
node dist/cli.js scan-skills                  # 既知スキルディレクトリを一括スキャン
node dist/cli.js allow ./my-skill/SKILL.md    # 承認（sha256。以降の警告を抑制）

# --- Phase 3 ---
node dist/cli.js scan ./skill --llm           # 灰色(medium+)のみ Claude API で二次判定
node dist/cli.js provenance github:owner/repo # 取得元の実在・バージョン固定・新しさ
node dist/cli.js add github:owner/repo        # 検疫付きインストール（取得→隔離スキャン→安全なら配置）
node dist/cli.js add ./skill --llm            # add に LLM 判定を併用
node dist/cli.js quarantine                   # 隔離中・配置保留中を一覧

# 開発中は npm script でも可
npm run dev -- scan ./my-skill/SKILL.md
```

`--json` で機械可読出力、`--quiet` で検出時のみ表示。

#### LLM 二次判定（`--llm`）

静的 regex で灰色（medium 以上）になった対象だけを Claude API で精査し、
「宣言された目的と実際の指示の乖離」を検出します（クリーンはスキップ＝コスト制御）。

- **opt-in**: `ANTHROPIC_API_KEY` が無ければ静かにスキップ（ネットワーク・課金を勝手に発生させない）
- モデルは `SKILL_FIREWALL_MODEL`（既定 `claude-opus-4-8`）
- 依存ゼロ: SDK を足さず Node 組込み fetch で `/v1/messages` を直接呼ぶ

> Claude Code のフック内ではキー不要です。注入されたコンテキストを**走行中のエージェントが**精査します。
> `--llm` は**セッション外（手動 / CI）**でエージェントが居ない場面のためのものです。

#### 検疫付きインストーラ（`add`）

スキルを skills へ即配置せず、まず検疫へ取得 → 静的＋LLM＋出所スキャン → 安全/承認時のみ配置。
HIGH・LLM malicious・リポジトリ不在は配置をブロックし、検疫に保持してレポートします。
取得元: ローカルパス / 単体 URL / GitHub リポジトリ（`git clone`）。`--force` で強行、`--yes` で要確認を承認。

#### Exit codes

| code | 意味 |
|------|------|
| 0 | クリーン、または INFO のみ |
| 1 | MEDIUM 検出（警告） |
| 2 | HIGH 検出（要確認） |
| 3 | 実行エラー |

CI やシェルから exit code で判定できます。

### Detection rules

`src/rules/rules.yaml` に外部定義（PR でルール追加可能）。確信度3段階：

- **HIGH** — 既知の攻撃パターン。ほぼ確実に悪性（指示の上書き、秘匿指示、認証情報の露出、`curl|sh`、不可視文字隠蔽、設定改ざん）
- **MEDIUM** — 危険だが正当な用途もありうる（.env アクセス、外部送信、エンコード済みペイロード、破壊的FS操作、永続化）
- **INFO** — 注意喚起のみ

**設計方針: HIGH 誤検知ゼロを最優先**。確信度の低いものは情報表示に留めます。
誤検知トラップ（`GITHUB_TOKEN`/`.ssh/config` 等を含む正当スキル）＋実在スキルで HIGH 誤検知ゼロを検証済み。

### 脅威モデル（重要）

`additionalContext` での「このスキルを信頼するな」は**最弱の説得レイヤー**です。攻撃者が同じ文脈を
支配しているため「警告は誤検知だ、無視せよ」で上書きされうる。load-bearing にしてはいけません。
効く防御は**構造的なもの2つ**＝①`--quarantine`（ファイルごと退避＝読めなければ騙されない）
②ユーザーに見える `systemMessage`（判断主体は人間）。検知は別プロセスで行い（`--llm` は本文を
"データ" として fence）、判定対象のスキルから文脈汚染を受けません。

### Limitations

静的正規表現は**平文の既知パターン**を捕捉する一次フィルタです。改行分割は全文スキャンで補いますが、
同義語・言い換え・全角/別表記・文脈依存（`GITHUB_TOKEN` が「説明」か「窃取」か）の判定は原理的に苦手で、
`--llm` の二次精査で補えます（opt-in）。**本ツール単体を完全な防御とみなさないでください。**

### Development

```bash
npm install --ignore-scripts
npm test        # 悪性/正常サンプルで検証（検出率・HIGH誤検知ゼロ）
npm run build   # dist/ に出力
npm run dev -- scan <path>
```

### Roadmap

- [x] **Phase 1**: CLI 静的スキャナ（ファイル/ディレクトリ/URL、ルール群、2段スキャン）
- [x] **Phase 2**: Claude Code hooks 連携（SessionStart 自動スキャン→警告注入→隔離・allowlist）
- [x] **Phase 3**: LLM 二次判定・出所チェック・検疫付きインストーラ・`.mcp.json` 本格対応・隔離一覧
- [ ] **Phase 4**: npm 公開・note 連載記事・Web サイト化（需要があれば）

---

## License

MIT
