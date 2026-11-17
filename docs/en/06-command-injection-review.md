# Command injection review (Claude Code 2.1.88)

Focus: shell interpolation / unsafe `child_process` usage. Return of validated MEDIUM+ only.

## HIGH — Shell-interpolated `which`/`where` on marketplace LSP `command`

- **Primary location:** `src/utils/which.ts`
- **Evidence:** `src/utils/which.ts:4-30,71-73`; `src/utils/binaryCheck.ts:14-35`; `src/utils/plugins/lspRecommendation.ts:112-141,278-279`; `src/utils/plugins/schemas.ts:710-725`; `src/hooks/useLspPluginRecommendation.tsx:78`; `QUICKSTART.md:13-14`; `README.md:206`
- **Attack path:**
  1. Attacker controls a plugin marketplace entry with inline `lspServers`.
  2. Sets `command` to a no-space payload that passes `LspServerConfigSchema` (e.g. `x;id`, `$(id)`, `/tmp/$(id)`).
  3. Victim has that marketplace configured.
  4. Victim opens a file with a matching extension → `getMatchingLspPlugins` → `isBinaryInstalled(command)` → `which(command)`.
  5. Published runtime is **Node** (`node cli.js`); `Bun` is undefined, so `whichNodeAsync` runs `execa(\`which ${command}\`, { shell: true })` (or `where.exe` on Windows) and executes the payload.
- **Impact:** RCE from marketplace metadata during a binary-existence check (not during intentional LSP spawn).
- **Mitigations that do NOT block it:** `LspServerConfigSchema` only rejects spaces (unless absolute path). `Bun.which` would be safe but is **not** used on the published Node bundle. Trust dialog does not gate marketplace LSP recommendation checks.

## MEDIUM — `CLAUDE_CODE_TMPDIR` interpolated into clipboard shell commands

- **Primary location:** `src/utils/imagePaste.ts`
- **Evidence:** `src/utils/imagePaste.ts:36-77,186-232`; `src/utils/managedEnv.ts:187-190`; `src/main.tsx:2585-2593`
- **Attack path:** Project `settings.env.CLAUDE_CODE_TMPDIR` with `$(...)` → applied after trust or under `-p` → clipboard image paste builds `osascript`/`rm`/`xclip` shell strings with the path in double quotes → POSIX shell expands substitutions.
- **Impact:** RCE on image paste without configuring `apiKeyHelper` / hooks.
- **Mitigations:** Not in `SAFE_ENV_VARS` (blocked pre-trust). After trust / `-p`, full project env applies; quoting with `"` does not stop `$()`.

## MEDIUM — `promptEditor` `execSync` string with contaminated path

- **Primary location:** `src/utils/promptEditor.ts`
- **Evidence:** `src/utils/promptEditor.ts:66-71`; `src/commands/keybindings/keybindings.ts:20-40`; `src/keybindings/loadUserBindings.ts:115-117`; `src/utils/envUtils.ts:7-14`; contrast `src/utils/editor.ts:107-111`
- **Attack path:** Project sets `CLAUDE_CONFIG_DIR` with command substitution → after trust/`-p` → `/keybindings` → `editFileInEditor` → `execSync(\`${editor} "${filePath}"\`)` expands `$()`.
- **Impact:** RCE when opening keybindings (or any `editFileInEditor` caller with a contaminated path).
- **Mitigations:** `editor.ts` already avoids shell on POSIX for this class of bug; `promptEditor.ts` was not updated. Pre-trust blocked for project env; post-trust/`-p` not.

## Reviewed and omitted (not MEDIUM+ injection with validated reachability)

- **auth.ts / headersHelper / otelHeadersHelper / hooks / statusLine:** intentional shell execution of configured helper/hook commands; gated by trust (interactive) or documented `-p` trust-skip. Not shell *interpolation* of non-command attacker fields.
- **windowsPaths `dir "${path}"` / `where.exe ${executable}`:** `findExecutable` only called with literal `'git'`; `CLAUDE_CODE_GIT_BASH_PATH` is user/env (project env only post-trust). Quote-breakout via `"` in Windows paths is largely unreachable (illegal filename char).
- **editor.ts Windows shell open:** `"` illegal in Win filenames; `&` safe inside quotes. POSIX path already argv/no-shell.
- **worktree/tmux `send-keys`:** uses `execFile` argv + `shell-quote` for the pane command string.
- **git clone / pluginLoader:** `execFile` argv; no shell concatenation of URLs.
- **deepLink terminalLauncher:** hardened `shellQuote` / `appleScriptQuote` / `cmdQuote`.
- **BashTool:** expected to run user/model commands after permission prompts (out of scope).
