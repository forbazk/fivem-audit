import type { ScanResult, Severity } from '../types.ts';
import { SEVERITIES } from '../types.ts';
import { NAME, VERSION } from '../version.ts';

interface Palette {
  bold(s: string): string;
  dim(s: string): string;
  severity(severity: Severity, s: string): string;
  score(score: number, s: string): string;
}

const ANSI = (code: string) => (s: string) => `\x1b[${code}m${s}\x1b[0m`;

function palette(color: boolean): Palette {
  if (!color) {
    return { bold: (s) => s, dim: (s) => s, severity: (_, s) => s, score: (_, s) => s };
  }
  const severityColor: Record<Severity, (s: string) => string> = {
    critical: ANSI('1;97;41'),
    high: ANSI('1;31'),
    medium: ANSI('33'),
    low: ANSI('36'),
    info: ANSI('2'),
  };
  return {
    bold: ANSI('1'),
    dim: ANSI('2'),
    severity: (severity, s) => severityColor[severity](s),
    score: (score, s) => (score >= 90 ? ANSI('32') : score >= 60 ? ANSI('33') : ANSI('31'))(s),
  };
}

export function grade(score: number): string {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

export function formatText(result: ScanResult, options: { color: boolean }): string {
  const c = palette(options.color);
  const lines: string[] = [];
  const { stats } = result;
  lines.push(
    c.bold(`${NAME} ${VERSION}`) +
      c.dim(`  ${result.resources.length} resource${result.resources.length === 1 ? '' : 's'} · ${stats.files} files · ${(stats.bytes / 1024).toFixed(0)} KiB · ${(stats.durationMs / 1000).toFixed(2)}s${stats.skipped ? ` · ${stats.skipped} skipped` : ''}`),
    '',
  );

  for (const resource of result.resources) {
    if (resource.findings.length === 0) continue;
    lines.push(`${c.bold(resource.name)}  ${c.score(resource.score, `${resource.score}/100 ${grade(resource.score)}`)}  ${c.dim(resource.path)}`);
    for (const f of resource.findings) {
      const label = c.severity(f.severity, ` ${f.severity.toUpperCase()} `.padEnd(10));
      lines.push(`  ${label} ${c.dim(f.ruleId)}  ${f.message}`);
      lines.push(`  ${' '.repeat(10)} ${c.dim(`${f.file}:${f.line}:${f.column}`)}`);
      const snippet = f.snippet.trim();
      if (snippet !== '') lines.push(`  ${' '.repeat(10)} ${c.dim('│')} ${snippet.length > 140 ? `${snippet.slice(0, 139)}…` : snippet}`);
    }
    lines.push('');
  }

  const clean = result.resources.filter((r) => r.findings.length === 0).length;
  if (result.findings.length === 0) {
    lines.push(c.score(100, `No issues found in ${result.resources.length} resource${result.resources.length === 1 ? '' : 's'}.`));
    return lines.join('\n');
  }
  const counts = [...SEVERITIES]
    .reverse()
    .map((s) => ({ s, n: result.findings.filter((f) => f.severity === s).length }))
    .filter((x) => x.n > 0)
    .map((x) => c.severity(x.s, `${x.n} ${x.s}`));
  lines.push(`${c.bold('Summary')}  ${counts.join(c.dim(' · '))}${clean ? c.dim(`  ·  ${clean} clean resource${clean === 1 ? '' : 's'}`) : ''}`);
  return lines.join('\n');
}
