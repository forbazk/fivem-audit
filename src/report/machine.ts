import { createHash } from 'node:crypto';
import { RULES } from '../rules/index.ts';
import type { ScanResult, Severity } from '../types.ts';
import { HOMEPAGE, NAME, VERSION } from '../version.ts';
import { grade } from './text.ts';

export function formatJson(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: { name: NAME, version: VERSION },
      roots: result.roots,
      stats: result.stats,
      resources: result.resources.map((r) => ({ ...r, grade: grade(r.score) })),
    },
    null,
    2,
  );
}

const LEVEL: Readonly<Record<Severity, 'error' | 'warning' | 'note'>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

export function formatSarif(result: ScanResult): string {
  const ruleIndex = new Map(RULES.map((r, i) => [r.id, i]));
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: NAME,
              version: VERSION,
              informationUri: HOMEPAGE,
              rules: RULES.map((r) => ({
                id: r.id,
                name: r.name,
                shortDescription: { text: r.name.replace(/-/g, ' ') },
                fullDescription: { text: r.description },
                helpUri: `${HOMEPAGE}#${r.id.toLowerCase()}`,
                defaultConfiguration: { level: LEVEL[r.severity] },
                properties: { tags: ['security', 'fivem'], 'security-severity': SECURITY_SEVERITY[r.severity] },
              })),
            },
          },
          results: result.findings.map((f) => ({
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
            level: LEVEL[f.severity],
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: encodeURI(f.uri) },
                  region: { startLine: f.line, startColumn: f.column },
                },
              },
            ],
            partialFingerprints: { primaryLocationLineHash: createHash('sha256').update(`${f.ruleId}|${f.file}|${f.snippet.trim()}`).digest('hex').slice(0, 32) },
            properties: { severity: f.severity, resource: f.resource },
          })),
        },
      ],
    },
    null,
    2,
  );
}
