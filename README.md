# fivem-audit

Static security scanner for FiveM resources. Point it at your `resources` folder and it reports backdoors, exploitable server events, SQL injection, leaked credentials and obfuscated code before they reach your server.

- **Zero runtime dependencies.** Nothing to trust but Node.js itself.
- **Never executes what it scans.** Files are only read and tokenized; symlinks are not followed.
- **Understands Lua and JavaScript.** Comments and string contents are masked by a real lexer, so a `load()` inside a comment is not a finding and a `PerformHttpRequest` hidden in `\x50\x65…` escapes is.
- **Manifest aware.** `fxmanifest.lua` globs decide which files run on the server, so client-only code does not raise server-side alerts.
- **Fast.** 135 MB of Lua across 3,000 files in under 3 seconds on a desktop CPU.
- **CI ready.** Text, JSON and SARIF output, meaningful exit codes, GitHub code scanning support.

```
$ npx github:forbazk/fivem-audit ./resources

fivem-audit 0.1.0  1 resource · 3 files · 1 KiB · 0.02s

vulnerable_shop  0/100 F  vulnerable_shop
   CRITICAL  FA003  string.char() builds "PerformHttpRequest" from 18 bytes
             vulnerable_shop/server/main.lua:12:11
   CRITICAL  FA002  PerformHttpRequest callback passes the response to load(): remote code execution
             vulnerable_shop/server/main.lua:14:1
   CRITICAL  FA008  Request target https://cipher-panel.me/_i/i?to=shop (known FiveM backdoor panel)
             vulnerable_shop/server/main.lua:14:21
   HIGH      FA006  Net event "shop:buy" passes client value "item", "amount" to addInventoryItem() without validating it
             vulnerable_shop/server/main.lua:3:11
   HIGH      FA005  SQL query built with string concatenation; use ? placeholders
             vulnerable_shop/server/main.lua:7:3
   HIGH      FA001  load() compiles a runtime value in a file that also performs HTTP requests
             vulnerable_shop/server/main.lua:15:16
   MEDIUM    FA004  Possible secret assigned to "LogApiKey"
             vulnerable_shop/config.lua:4:21

Summary  3 critical · 3 high · 1 medium
```

The sample above comes from [`examples/vulnerable_shop`](examples/vulnerable_shop).

## Install

Requires Node.js 20 or newer.

```sh
npx github:forbazk/fivem-audit ./resources
```

Or clone and build:

```sh
git clone https://github.com/forbazk/fivem-audit
cd fivem-audit
npm ci
npm run build
node dist/cli.js /path/to/resources
```

## Usage

```
fivem-audit [paths...] [options]

  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
      --fail-on <severity>         Exit with code 1 at or above this severity (default: high, "none" to disable)
      --min-severity <severity>    Hide findings below this severity (default: low)
      --rules <ids>                Only run these rules, comma separated
      --exclude-rules <ids>        Skip these rules, comma separated
  -i, --ignore <glob>              Ignore paths matching the glob (repeatable)
      --max-file-size <kb>         Skip files larger than this (default: 2048)
  -j, --concurrency <n>            Files read in parallel (default: auto)
      --no-color                   Disable colors
      --list-rules                 Print the rule catalog and exit
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or runtime error.

Each resource gets a score out of 100 (critical −40, high −15, medium −5, low −1) and a grade from A to F, so the worst offenders are listed first.

## Rules

| ID | Severity | Detects |
| --- | --- | --- |
| <a id="fa001"></a>FA001 | medium–high | `load`, `loadstring`, `dofile`, `eval`, `new Function` on runtime values. Escalated when the same file makes HTTP requests, lowered for constants and files bundled with the resource. |
| <a id="fa002"></a>FA002 | critical | An HTTP response executed as code: the classic remote-controlled backdoor. |
| <a id="fa003"></a>FA003 | low–critical | Byte-escaped strings, `string.char` chains, `_G[...]` lookups and packed lines. Critical when the hidden text is an API name such as `PerformHttpRequest`. |
| <a id="fa004"></a>FA004 | medium–critical | Discord webhooks and bot tokens, GitHub, Stripe, AWS and Slack keys, private keys, `sv_licenseKey`, Steam Web API keys, database passwords. Values are redacted in every report. |
| <a id="fa005"></a>FA005 | high | oxmysql, mysql-async and ghmattimysql queries built with `..`, `string.format` or template literals instead of `?` placeholders. |
| <a id="fa006"></a>FA006 | medium–high | `RegisterNetEvent` / `onNet` handlers that pass client arguments into money, item, weapon, job or permission functions. |
| <a id="fa007"></a>FA007 | medium–critical | `os.execute`, `io.popen`, raw file access, `child_process`, and `ExecuteCommand` built from runtime values. |
| <a id="fa008"></a>FA008 | low–critical | Requests to known backdoor panels, paste sites, tunnels and raw public IP addresses. |
| <a id="fa009"></a>FA009 | info | Deprecated `__resource.lua` manifests. |

## Suppressing findings

Add a comment on the same line or the line above:

```lua
local fn = load(chunk) -- fivem-audit-ignore FA001
```

Omit the rule ID to silence every rule on that line. Put `fivem-audit-ignore-file` in the first lines of a file to skip it entirely.

## GitHub Actions

```yaml
name: Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  fivem-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx --yes github:forbazk/fivem-audit . --format sarif --output fivem-audit.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: fivem-audit.sarif
```

Findings then appear in the repository's **Security → Code scanning** tab and as annotations on pull requests.

## Programmatic API

```ts
import { scan, formatSarif } from 'fivem-audit';

const result = await scan(['./resources'], { minSeverity: 'medium' });
for (const resource of result.resources) {
  console.log(resource.name, resource.score, resource.findings.length);
}
```

## Limitations

fivem-audit is a static analyzer built on lexing and targeted pattern analysis, not a full interpreter. It catches the patterns real backdoors and exploits rely on, but a determined author can still hide code from it. Treat a clean report as a strong signal, not a guarantee, and keep reviewing resources from untrusted sources by hand.

## License

[MIT](LICENSE)
