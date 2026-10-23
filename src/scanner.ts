import { lstat, open, readdir, readFile } from 'node:fs/promises';
import { availableParallelism } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { EMPTY_MANIFEST, globToRegExp, parseManifest, sideOf } from './manifest.ts';
import type { Manifest } from './manifest.ts';
import { RULES } from './rules/index.ts';
import { createSource } from './source.ts';
import type { Finding, Language, ResourceResult, Rule, ScanOptions, ScanResult, Severity, SourceFile } from './types.ts';
import { severityRank } from './types.ts';

const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', '.idea', '.vscode', 'stream', '__MACOSX']);
const LANGUAGES: Readonly<Record<string, Language>> = {
  '.lua': 'lua',
  '.js': 'js',
  '.mjs': 'js',
  '.cjs': 'js',
  '.ts': 'js',
  '.jsx': 'js',
  '.tsx': 'js',
  '.json': 'text',
  '.cfg': 'text',
  '.env': 'text',
  '.yml': 'text',
  '.yaml': 'text',
  '.toml': 'text',
  '.ini': 'text',
  '.sql': 'text',
  '.html': 'text',
};
const MANIFESTS = ['fxmanifest.lua', '__resource.lua'] as const;
const PENALTY: Readonly<Record<Severity, number>> = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };
const SUPPRESS = /fivem-audit-ignore(?!-file)(?:[ \t]+((?:FA\d{3}[ \t,]*)+))?/;

interface Resource {
  name: string;
  dir: string;
  path: string;
  manifest: Manifest;
  kind: ResourceResult['manifest'];
  files: number;
  findings: Finding[];
}

interface Candidate {
  readonly absolutePath: string;
  readonly base: string;
  readonly language: Language;
  readonly resource: Resource;
}

function languageOf(file: string): Language | undefined {
  const name = basename(file).toLowerCase();
  if (name === '.env' || name.startsWith('.env.')) return 'text';
  const dot = name.lastIndexOf('.');
  return dot === -1 ? undefined : LANGUAGES[name.slice(dot)];
}

function toPosix(path: string): string {
  return sep === '/' ? path : path.split(sep).join('/');
}

async function isBinary(path: string): Promise<boolean> {
  const handle = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await handle.close();
  }
}

function suppressed(file: SourceFile, finding: Finding): boolean {
  for (const line of [finding.line, finding.line - 1]) {
    if (line < 1) continue;
    const m = SUPPRESS.exec(file.lineText(line));
    if (m === null) continue;
    if (m[1] === undefined || m[1].includes(finding.ruleId)) return true;
  }
  return false;
}

function redactSnippet(snippet: string, column: number, length: number): string {
  const start = column - 1;
  const keep = Math.min(4, length);
  return snippet.slice(0, start + keep) + '*'.repeat(Math.max(0, Math.min(length, snippet.length - start) - keep)) + snippet.slice(start + length);
}

export function analyze(file: SourceFile, rules: readonly Rule[] = RULES, minSeverity: Severity = 'info'): Finding[] {
  if (/fivem-audit-ignore-file/.test(file.text.slice(0, 2000))) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const floor = severityRank(minSeverity);
  for (const rule of rules) {
    if (!rule.languages.includes(file.language)) continue;
    rule.check(file, (match) => {
      const severity = match.severity ?? rule.severity;
      if (severityRank(severity) < floor) return;
      const { line, column } = file.position(match.offset);
      const key = `${rule.id}:${line}:${column}`;
      if (seen.has(key)) return;
      seen.add(key);
      let snippet = file.lineText(line);
      if (match.redact) snippet = redactSnippet(snippet, column, match.length ?? 0);
      const finding: Finding = {
        ruleId: rule.id,
        severity,
        message: match.message,
        resource: file.resource,
        file: file.path,
        line,
        column,
        snippet: snippet.length > 240 ? `${snippet.slice(Math.max(0, column - 80), Math.max(0, column - 80) + 240)}` : snippet,
      };
      if (!suppressed(file, finding)) findings.push(finding);
    });
  }
  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

export async function scan(roots: readonly string[], options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const concurrency = Math.max(1, options.concurrency ?? Math.min(16, availableParallelism() * 2));
  const ignore = (options.ignore ?? []).map(globToRegExp);
  const rules = options.rules ?? RULES;
  const minSeverity = options.minSeverity ?? 'info';
  const resolvedRoots = roots.map((r) => resolve(r));
  const resources = new Map<string, Resource>();
  const candidates: Candidate[] = [];
  let skipped = 0;

  const resourceFor = async (dir: string, root: string, parent: Resource | undefined): Promise<Resource | undefined> => {
    for (const name of MANIFESTS) {
      const path = join(dir, name);
      try {
        const info = await lstat(path);
        if (!info.isFile()) continue;
        const text = info.size <= maxFileSize ? await readFile(path, 'utf8') : '';
        const resource: Resource = {
          name: basename(dir) || dir,
          dir,
          path: toPosix(relative(root, dir)) || '.',
          manifest: parseManifest(text),
          kind: name === 'fxmanifest.lua' ? 'fxmanifest' : 'legacy',
          files: 0,
          findings: [],
        };
        resources.set(dir, resource);
        return resource;
      } catch {
        continue;
      }
    }
    return parent;
  };

  const looseResource = (root: string): Resource => {
    const key = `${root}\0loose`;
    let resource = resources.get(key);
    if (resource === undefined) {
      resource = { name: basename(root) || root, dir: '', path: '.', manifest: EMPTY_MANIFEST, kind: 'none', files: 0, findings: [] };
      resources.set(key, resource);
    }
    return resource;
  };

  const walk = async (dir: string, root: string, parent: Resource | undefined): Promise<void> => {
    const resource = await resourceFor(dir, root, parent);
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      skipped++;
      return;
    }
    const subdirs: string[] = [];
    for (const entry of entries) {
      const path = join(dir, entry.name);
      const rel = toPosix(relative(root, path));
      if (ignore.some((r) => r.test(rel) || r.test(entry.name))) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) subdirs.push(path);
        continue;
      }
      if (!entry.isFile()) continue;
      const language = languageOf(entry.name);
      if (language === undefined) continue;
      candidates.push({ absolutePath: path, base: root, language, resource: resource ?? looseResource(root) });
    }
    await Promise.all(subdirs.map((d) => walk(d, root, resource)));
  };

  for (const root of resolvedRoots) {
    const info = await lstat(root);
    if (info.isDirectory()) {
      await walk(root, root, undefined);
    } else if (info.isFile()) {
      const language = languageOf(root);
      if (language !== undefined) candidates.push({ absolutePath: root, base: dirname(root), language, resource: looseResource(root) });
    }
  }

  let bytes = 0;
  let files = 0;
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < candidates.length) {
      const candidate = candidates[cursor++]!;
      try {
        const info = await lstat(candidate.absolutePath);
        if (info.size > maxFileSize || (await isBinary(candidate.absolutePath))) {
          skipped++;
          continue;
        }
        const text = (await readFile(candidate.absolutePath, 'utf8')).replace(/^﻿/, '');
        const inResource = toPosix(relative(candidate.resource.dir === '' ? candidate.base : candidate.resource.dir, candidate.absolutePath));
        const source = createSource({
          absolutePath: candidate.absolutePath,
          path: toPosix(relative(candidate.base, candidate.absolutePath)) || basename(candidate.absolutePath),
          resource: candidate.resource.name,
          language: candidate.language,
          side: sideOf(candidate.resource.manifest, inResource),
          text,
        });
        candidate.resource.findings.push(...analyze(source, rules, minSeverity));
        candidate.resource.files++;
        bytes += info.size;
        files++;
      } catch {
        skipped++;
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  const results: ResourceResult[] = [...resources.values()]
    .filter((r) => r.files > 0 || r.kind !== 'none')
    .map((r) => ({
      name: r.name,
      path: r.path,
      manifest: r.kind,
      files: r.files,
      score: Math.max(0, 100 - r.findings.reduce((sum, f) => sum + PENALTY[f.severity], 0)),
      findings: r.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line),
    }))
    .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));

  return {
    roots: resolvedRoots.map((r) => toPosix(relative(process.cwd(), r)) || '.'),
    resources: results,
    findings: results.flatMap((r) => r.findings),
    stats: { files, skipped, bytes, durationMs: Math.round(performance.now() - started) },
  };
}
